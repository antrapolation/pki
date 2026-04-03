defmodule PkiCaEngine.CeremonyOrchestrator do
  @moduledoc """
  Orchestrates multi-participant ceremony phase transitions.

  Handles:
  - Creating ceremonies with participant assignments
  - Tracking custodian readiness
  - Recording auditor attestations
  - Triggering atomic key generation when all participants are ready
  """

  alias PkiCaEngine.TenantRepo
  alias PkiCaEngine.Schema.{KeyCeremony, ThresholdShare, CeremonyAttestation}
  alias PkiCaEngine.{IssuerKeyManagement, KeystoreManagement}
  alias PkiCaEngine.KeyCeremony.{SyncCeremony, ShareEncryption}
  import Ecto.Query

  @doc """
  Initiates a ceremony with participant assignments.

  Creates KeyCeremony, IssuerKey, and placeholder ThresholdShare records.
  """
  def initiate(tenant_id, ca_instance_id, params) do
    repo = TenantRepo.ca_repo(tenant_id)

    with :ok <- validate_threshold(params.threshold_k, params.threshold_n),
         :ok <- validate_participants(params.custodian_user_ids, params.threshold_n),
         {:ok, _keystore} <- KeystoreManagement.get_keystore(tenant_id, params.keystore_id) do
      window_hours = Map.get(params, :time_window_hours, 24)
      window_expires_at = DateTime.utc_now() |> DateTime.add(window_hours * 3600, :second) |> DateTime.truncate(:second)

      repo.transaction(fn ->
        case IssuerKeyManagement.create_issuer_key(tenant_id, ca_instance_id, %{
               key_alias: Map.get(params, :key_alias) || "key-#{System.unique_integer([:positive])}",
               algorithm: params.algorithm,
               is_root: Map.get(params, :is_root, true),
               threshold_config: %{k: params.threshold_k, n: params.threshold_n}
             }) do
          {:ok, issuer_key} ->
            ceremony_attrs = %{
              ca_instance_id: ca_instance_id,
              issuer_key_id: issuer_key.id,
              ceremony_type: "sync",
              status: "preparing",
              algorithm: params.algorithm,
              keystore_id: params.keystore_id,
              threshold_k: params.threshold_k,
              threshold_n: params.threshold_n,
              domain_info: Map.get(params, :domain_info, %{}),
              initiated_by: params.initiated_by,
              auditor_user_id: params.auditor_user_id,
              time_window_hours: window_hours,
              window_expires_at: window_expires_at,
              participants: %{
                custodians: params.custodian_user_ids,
                auditor: params.auditor_user_id
              }
            }

            case %KeyCeremony{} |> KeyCeremony.changeset(ceremony_attrs) |> repo.insert() do
              {:ok, ceremony} ->
                # Create placeholder shares for each custodian
                shares =
                  params.custodian_user_ids
                  |> Enum.with_index(1)
                  |> Enum.map(fn {user_id, index} ->
                    {:ok, share} =
                      %ThresholdShare{}
                      |> ThresholdShare.placeholder_changeset(%{
                        issuer_key_id: issuer_key.id,
                        custodian_user_id: user_id,
                        share_index: index,
                        min_shares: params.threshold_k,
                        total_shares: params.threshold_n,
                        status: "pending"
                      })
                      |> repo.insert()

                    share
                  end)

                {ceremony, issuer_key, shares}

              {:error, reason} ->
                repo.rollback(reason)
            end

          {:error, reason} ->
            repo.rollback(reason)
        end
      end)
    end
  end

  @doc """
  Records a custodian accepting their share (key_label stored in DB, password NOT stored in DB).
  """
  def accept_share(tenant_id, ceremony_id, user_id, key_label) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.status == "preparing" ->
        case repo.one(
               from s in ThresholdShare,
                 where: s.issuer_key_id == ^ceremony.issuer_key_id and
                        s.custodian_user_id == ^user_id and
                        s.status == "pending"
             ) do
          nil ->
            {:error, :share_not_found}

          share ->
            share
            |> Ecto.Changeset.change(%{
              key_label: key_label,
              status: "accepted",
              accepted_at: DateTime.utc_now() |> DateTime.truncate(:second)
            })
            |> repo.update()
        end

      {:ok, _} -> {:error, :invalid_ceremony_status}
      error -> error
    end
  end

  @doc """
  Records an auditor attestation for a ceremony phase.
  """
  def attest(tenant_id, ceremony_id, auditor_user_id, phase, details \\ %{}) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.auditor_user_id == auditor_user_id ->
        %CeremonyAttestation{}
        |> CeremonyAttestation.changeset(%{
          ceremony_id: ceremony_id,
          auditor_user_id: auditor_user_id,
          phase: phase,
          attested_at: DateTime.utc_now() |> DateTime.truncate(:second),
          details: details
        })
        |> repo.insert()

      {:ok, _} -> {:error, :not_assigned_auditor}
      error -> error
    end
  end

  @doc """
  Checks if all custodians have accepted and preparation attestation exists.
  Returns :ready if the ceremony can proceed to key generation.
  """
  def check_readiness(tenant_id, ceremony_id) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.status == "preparing" ->
        all_accepted =
          repo.aggregate(
            from(s in ThresholdShare,
              where: s.issuer_key_id == ^ceremony.issuer_key_id and s.status == "pending"
            ),
            :count
          ) == 0

        prep_attested =
          repo.exists?(
            from(a in CeremonyAttestation,
              where: a.ceremony_id == ^ceremony_id and a.phase == "preparation"
            )
          )

        if all_accepted and prep_attested, do: :ready, else: :waiting

      {:ok, _} -> {:error, :invalid_status}
      error -> error
    end
  end

  @doc """
  Executes atomic key generation: keygen -> sign -> split -> encrypt -> wipe.

  `custodian_passwords` is a list of `{user_id, password}` tuples from ETS.
  """
  def execute_keygen(tenant_id, ceremony_id, custodian_passwords) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_ceremony(repo, ceremony_id) do
      {:ok, ceremony} when ceremony.status == "preparing" ->
        # Transition to generating
        ceremony
        |> Ecto.Changeset.change(%{status: "generating"})
        |> repo.update!()

        # Build a password lookup map keyed by user_id for safe ordering
        password_map = Map.new(custodian_passwords)

        # Load shares ordered by share_index to ensure deterministic ordering
        db_shares = repo.all(
          from s in ThresholdShare,
            where: s.issuer_key_id == ^ceremony.issuer_key_id,
            order_by: [asc: s.share_index]
        )

        # Generate keypair
        case SyncCeremony.generate_keypair(ceremony.algorithm) do
          {:ok, %{public_key: pub, private_key: priv}} ->
            fingerprint = :crypto.hash(:sha256, pub) |> Base.encode16(case: :lower)

            is_root = Map.get(ceremony.domain_info || %{}, "is_root", true)
            subject_dn = Map.get(ceremony.domain_info || %{}, "subject_dn", "/CN=CA-#{ceremony.id}")

            # Sign cert or generate CSR
            {cert_or_csr_result, cert_der, cert_pem, csr_pem} =
              if is_root do
                case generate_self_signed(priv, subject_dn) do
                  {:ok, der, pem} -> {:ok, der, pem, nil}
                  error -> {error, nil, nil, nil}
                end
              else
                case generate_csr(priv, subject_dn) do
                  {:ok, pem} -> {:ok, nil, nil, pem}
                  error -> {error, nil, nil, nil}
                end
              end

            case cert_or_csr_result do
              :ok ->
                # Split private key — shares come out in index order
                case PkiCrypto.Shamir.split(priv, ceremony.threshold_k, ceremony.threshold_n) do
                  {:ok, raw_shares} ->
                    # Wipe private key immediately after split
                    _priv = nil

                    # Encrypt each share with the correct custodian's password,
                    # matching by share_index (db_shares ordered by share_index,
                    # raw_shares ordered by split index)
                    encrypted_pairs =
                      Enum.zip(db_shares, raw_shares)
                      |> Enum.map(fn {db_share, raw_share} ->
                        password = Map.fetch!(password_map, db_share.custodian_user_id)
                        {:ok, encrypted} = ShareEncryption.encrypt_share(raw_share, password)
                        {db_share, encrypted}
                      end)

                    # All DB writes in a transaction
                    case repo.transaction(fn ->
                      # Update each share with encrypted data
                      Enum.each(encrypted_pairs, fn {db_share, encrypted_share} ->
                        db_share
                        |> Ecto.Changeset.change(%{encrypted_share: encrypted_share})
                        |> repo.update!()
                      end)

                      # Activate issuer key if root CA
                      if is_root and cert_der do
                        issuer_key = repo.get!(PkiCaEngine.Schema.IssuerKey, ceremony.issuer_key_id)
                        IssuerKeyManagement.activate_by_certificate(tenant_id, issuer_key, %{
                          certificate_der: cert_der,
                          certificate_pem: cert_pem
                        })
                      end

                      # Update ceremony to completed
                      ceremony = repo.get!(KeyCeremony, ceremony_id)
                      ceremony
                      |> Ecto.Changeset.change(%{
                        status: "completed",
                        domain_info: Map.merge(ceremony.domain_info || %{}, %{
                          "fingerprint" => fingerprint,
                          "csr_pem" => csr_pem,
                          "subject_dn" => subject_dn
                        })
                      })
                      |> repo.update!()
                    end) do
                      {:ok, _} ->
                        # Wipe all sensitive variables and force GC
                        _raw_shares = nil
                        _encrypted_pairs = nil
                        _password_map = nil
                        :erlang.garbage_collect()

                        {:ok, %{fingerprint: fingerprint, csr_pem: csr_pem}}

                      {:error, reason} ->
                        fail_ceremony(repo, ceremony_id, "transaction_failed: #{inspect(reason)}")
                        {:error, reason}
                    end

                  error ->
                    fail_ceremony(repo, ceremony_id, "shamir_split_failed")
                    error
                end

              error ->
                fail_ceremony(repo, ceremony_id, "cert_generation_failed")
                error
            end

          error ->
            fail_ceremony(repo, ceremony_id, "keygen_failed")
            error
        end

      {:ok, _} -> {:error, :invalid_status}
      error -> error
    end
  end

  @doc """
  Marks a ceremony as failed.
  """
  def fail_ceremony(nil, ceremony_id, reason) do
    fail_ceremony(PkiCaEngine.Repo, ceremony_id, reason)
  end

  def fail_ceremony(tenant_id, ceremony_id, reason) when is_binary(tenant_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    fail_ceremony(repo, ceremony_id, reason)
  end

  def fail_ceremony(repo, ceremony_id, reason) do
    case repo.get(KeyCeremony, ceremony_id) do
      nil -> {:error, :not_found}
      ceremony ->
        ceremony
        |> Ecto.Changeset.change(%{
          status: "failed",
          domain_info: Map.merge(ceremony.domain_info || %{}, %{"failure_reason" => reason})
        })
        |> repo.update()
    end
  end

  @doc """
  Lists attestations for a ceremony.
  """
  def list_attestations(tenant_id, ceremony_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    repo.all(from a in CeremonyAttestation, where: a.ceremony_id == ^ceremony_id, order_by: [asc: a.attested_at])
  end

  # --- Private helpers ---

  defp get_ceremony(repo, ceremony_id) do
    case repo.get(KeyCeremony, ceremony_id) do
      nil -> {:error, :not_found}
      ceremony -> {:ok, ceremony}
    end
  end

  defp validate_threshold(k, n) when is_integer(k) and is_integer(n) and k >= 2 and k <= n, do: :ok
  defp validate_threshold(_, _), do: {:error, :invalid_threshold}

  defp validate_participants(user_ids, n) when is_list(user_ids) and length(user_ids) == n, do: :ok
  defp validate_participants(_, _), do: {:error, :participant_count_mismatch}

  defp generate_self_signed(private_key_der, subject_dn) do
    try do
      native_key = decode_private_key(private_key_der)
      root_cert = X509.Certificate.self_signed(native_key, subject_dn,
        template: :root_ca, hash: :sha256, serial: {:random, 8}, validity: 365 * 25)
      cert_der = X509.Certificate.to_der(root_cert)
      cert_pem = X509.Certificate.to_pem(root_cert)
      {:ok, cert_der, cert_pem}
    rescue
      e -> {:error, e}
    end
  end

  defp generate_csr(private_key_der, subject_dn) do
    try do
      native_key = decode_private_key(private_key_der)
      csr = X509.CSR.new(native_key, subject_dn)
      {:ok, X509.CSR.to_pem(csr)}
    rescue
      e -> {:error, e}
    end
  end

  defp decode_private_key(der) do
    try do
      :public_key.der_decode(:RSAPrivateKey, der)
    rescue
      _ -> :public_key.der_decode(:ECPrivateKey, der)
    end
  end
end
