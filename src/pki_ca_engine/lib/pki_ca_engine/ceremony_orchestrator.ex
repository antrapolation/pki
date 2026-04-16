defmodule PkiCaEngine.CeremonyOrchestrator do
  @moduledoc """
  Orchestrates key ceremony lifecycle.

  Redesigned for Mnesia:
  - Ceremony participants are name+password (not portal user FKs)
  - Auditor identity verification gate
  - Printable transcript (CeremonyTranscript)
  - Root CA requires full ceremony; sub-CA supports full or simplified
  - Single session: initiate -> verify identities -> generate -> distribute -> complete

  ## Key Material Handling

  During `execute_keygen/2`, raw private key bytes exist in BEAM process memory
  from keypair generation through Shamir splitting and share encryption. The BEAM
  does not offer a guaranteed way to zero memory after use -- binaries may be
  reference-counted and remain on the heap until garbage-collected.

  Mitigations applied:
  - `:erlang.garbage_collect()` is called immediately after the private key is
    split into shares and again after the encrypted shares are committed.
  - The raw private key is never stored in GenServer state or ETS; it lives only
    as a local variable within `do_keygen_and_split/3`.

  Residual risk: a heap dump, core dump, or `:erlang.process_info(pid, :messages)`
  call during the brief keygen window could expose the raw key. For environments
  requiring stronger guarantees, key generation should be delegated to an HSM or
  a NIF that manages its own memory (see the HSM keystore provider).

  ## Password Hashing

  Custodian share-acceptance passwords are hashed with PBKDF2-HMAC-SHA256
  (100 000 iterations, 16-byte random salt). The `password_hash` field stores
  `<<salt::binary-16, hash::binary-32>>` (48 bytes total).
  """

  require Logger

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{
    KeyCeremony, IssuerKey, ThresholdShare,
    CeremonyParticipant, CeremonyTranscript
  }
  alias PkiCaEngine.{IssuerKeyManagement, CaInstanceManagement}
  alias PkiCaEngine.KeyCeremony.{SyncCeremony, ShareEncryption}

  @doc """
  Initiate a ceremony. Creates KeyCeremony, IssuerKey, CeremonyParticipants, and CeremonyTranscript.

  params:
    - ca_instance_id: binary
    - algorithm: string (e.g., "ML-DSA-65")
    - threshold_k: integer (minimum shares to reconstruct)
    - threshold_n: integer (total shares)
    - custodian_names: list of strings (custodian names, NOT user IDs)
    - auditor_name: string (auditor name)
    - ceremony_mode: :full | :simplified (root CA must be :full)
    - key_alias: optional string
    - subject_dn: optional string
    - is_root: boolean (default true)
    - initiated_by: string (name of person initiating)
  """
  def initiate(ca_instance_id, params) do
    with :ok <- validate_threshold(params.threshold_k, params.threshold_n),
         :ok <- validate_participants(params.custodian_names, params.threshold_n),
         :ok <- validate_ceremony_mode(params) do

      Repo.transaction(fn ->
        # Create issuer key
        key = IssuerKey.new(%{
          ca_instance_id: ca_instance_id,
          key_alias: Map.get(params, :key_alias, "key-#{:erlang.unique_integer([:positive])}"),
          algorithm: params.algorithm,
          is_root: Map.get(params, :is_root, true),
          ceremony_mode: Map.get(params, :ceremony_mode, :full),
          threshold_config: %{k: params.threshold_k, n: params.threshold_n}
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(IssuerKey), key))

        # Create ceremony
        window_hours = Map.get(params, :time_window_hours, 24)
        window_expires_at = DateTime.utc_now() |> DateTime.add(window_hours * 3600, :second) |> DateTime.truncate(:second)

        ceremony = KeyCeremony.new(%{
          ca_instance_id: ca_instance_id,
          issuer_key_id: key.id,
          algorithm: params.algorithm,
          threshold_k: params.threshold_k,
          threshold_n: params.threshold_n,
          domain_info: %{
            "is_root" => Map.get(params, :is_root, true),
            "subject_dn" => Map.get(params, :subject_dn, "/CN=CA-#{ca_instance_id}")
          },
          initiated_by: params.initiated_by,
          window_expires_at: window_expires_at
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(KeyCeremony), ceremony))

        # Create custodian participants
        custodian_participants =
          params.custodian_names
          |> Enum.map(fn name ->
            p = CeremonyParticipant.new(%{ceremony_id: ceremony.id, name: name, role: :custodian})
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyParticipant), p))
            p
          end)

        # Create auditor participant
        auditor = CeremonyParticipant.new(%{
          ceremony_id: ceremony.id,
          name: params.auditor_name,
          role: :auditor
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyParticipant), auditor))

        # Create placeholder shares for each custodian
        shares =
          params.custodian_names
          |> Enum.with_index(1)
          |> Enum.map(fn {name, index} ->
            share = ThresholdShare.new(%{
              issuer_key_id: key.id,
              custodian_name: name,
              share_index: index,
              min_shares: params.threshold_k,
              total_shares: params.threshold_n,
              status: "pending"
            })
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(ThresholdShare), share))
            share
          end)

        # Create transcript
        transcript = CeremonyTranscript.new(%{
          ceremony_id: ceremony.id,
          entries: [%{
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            actor: params.initiated_by,
            action: "ceremony_initiated",
            details: %{algorithm: params.algorithm, k: params.threshold_k, n: params.threshold_n}
          }]
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyTranscript), transcript))

        {ceremony, key, shares, custodian_participants ++ [auditor], transcript}
      end)
    end
  end

  @doc """
  Verify a participant's identity. The auditor confirms they verified a custodian.
  This is the identity verification gate required before key generation.
  """
  def verify_identity(ceremony_id, custodian_name, auditor_name) do
    case Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony_id) do
      {:ok, participants} ->
        case Enum.find(participants, fn p -> p.name == custodian_name and p.role == :custodian end) do
          nil -> {:error, :participant_not_found}
          participant ->
            Repo.transaction(fn ->
              now = DateTime.utc_now() |> DateTime.truncate(:second)
              updated = %{participant | identity_verified_by: auditor_name, identity_verified_at: now}
              :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyParticipant), updated))

              append_transcript_in_tx(ceremony_id, auditor_name, "identity_verified", %{custodian: custodian_name})

              updated
            end)
        end
      {:error, _} = err -> err
    end
  end

  @doc """
  Accept a custodian's share assignment with their password.
  Stores a password hash for later share encryption.
  """
  def accept_share(ceremony_id, custodian_name, password) do
    with {:ok, ceremony} <- get_ceremony(ceremony_id),
         true <- ceremony.status == "preparing" || {:error, :invalid_ceremony_status} do

      case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id) do
        {:ok, shares} ->
          case Enum.find(shares, fn s -> s.custodian_name == custodian_name and s.status == "pending" end) do
            nil -> {:error, :share_not_found}
            share ->
              salt = :crypto.strong_rand_bytes(16)
              password_hash = :crypto.pbkdf2_hmac(:sha256, password, salt, 100_000, 32)
              combined_hash = salt <> password_hash
              now = DateTime.utc_now() |> DateTime.truncate(:second)

              Repo.transaction(fn ->
                updated = %{share | password_hash: combined_hash, status: "accepted", updated_at: now}
                :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(ThresholdShare), updated))

                append_transcript_in_tx(ceremony_id, custodian_name, "share_accepted", %{})

                updated
              end)
          end
        {:error, _} = err -> err
      end
    end
  end

  @doc """
  Check if all custodians have been identity-verified and accepted their shares.
  Returns :ready or :waiting.
  """
  def check_readiness(ceremony_id) do
    with {:ok, ceremony} <- get_ceremony(ceremony_id),
         true <- ceremony.status == "preparing" || {:error, :invalid_status} do

      with {:ok, all_participants} <- Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony_id),
           participants = Enum.filter(all_participants, fn p -> p.role == :custodian end),
           {:ok, shares} <- Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id) do

        all_verified = Enum.all?(participants, fn p -> p.identity_verified_at != nil end)
        all_accepted = Enum.all?(shares, fn s -> s.status == "accepted" end)

        if all_verified and all_accepted, do: :ready, else: :waiting
      end
    end
  end

  @doc """
  Execute key generation: keygen -> sign -> split -> encrypt per custodian password -> wipe.
  custodian_passwords: list of {custodian_name, password} tuples.
  """
  def execute_keygen(ceremony_id, custodian_passwords) do
    with {:ok, ceremony} <- get_ceremony(ceremony_id),
         true <- ceremony.status in ["preparing", "generating"] || {:error, :invalid_status} do

      # Claim ceremony
      {:ok, _} = Repo.update(ceremony, %{status: "generating"})

      case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id) do
        {:ok, db_shares} ->
          db_shares = Enum.sort_by(db_shares, & &1.share_index)
          password_map = Map.new(custodian_passwords)
          do_keygen_and_split(ceremony, db_shares, password_map)

        {:error, _} = err -> err
      end
    end
  end

  @doc "Mark a ceremony as failed."
  def fail_ceremony(ceremony_id, reason) do
    case Repo.get(KeyCeremony, ceremony_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ceremony} ->
        Repo.update(ceremony, %{
          status: "failed",
          domain_info: Map.merge(ceremony.domain_info || %{}, %{"failure_reason" => reason})
        })
      {:error, _} = err -> err
    end
  end

  @doc "Get the transcript for a ceremony."
  def get_transcript(ceremony_id) do
    case Repo.get_all_by_index(CeremonyTranscript, :ceremony_id, ceremony_id) do
      {:ok, []} -> {:error, :not_found}
      {:ok, [t | _]} -> {:ok, t}
      {:error, _} = err -> err
    end
  end

  @doc "List participants for a ceremony."
  def list_participants(ceremony_id) do
    Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony_id)
  end

  # -- Private --

  defp get_ceremony(ceremony_id) do
    case Repo.get(KeyCeremony, ceremony_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ceremony} -> {:ok, ceremony}
      {:error, _} = err -> err
    end
  end

  defp do_keygen_and_split(ceremony, db_shares, passwords) do
    case SyncCeremony.generate_keypair(ceremony.algorithm) do
      {:ok, %{public_key: pub, private_key: priv}} ->
        fingerprint = :crypto.hash(:sha256, pub) |> Base.encode16(case: :lower)
        is_root = Map.get(ceremony.domain_info, "is_root", true)
        subject_dn = Map.get(ceremony.domain_info, "subject_dn", "/CN=CA-#{ceremony.id}")

        {cert_or_csr_result, cert_der, cert_pem, csr_pem} =
          if is_root do
            case generate_self_signed(ceremony.algorithm, priv, pub, subject_dn) do
              {:ok, der, pem} -> {:ok, der, pem, nil}
              error -> {error, nil, nil, nil}
            end
          else
            case generate_csr(ceremony.algorithm, priv, pub, subject_dn) do
              {:ok, pem} -> {:ok, nil, nil, pem}
              error -> {error, nil, nil, nil}
            end
          end

        case cert_or_csr_result do
          :ok ->
            case PkiCrypto.Shamir.split(priv, ceremony.threshold_k, ceremony.threshold_n) do
              {:ok, raw_shares} ->
                :erlang.garbage_collect()
                encrypt_and_commit(ceremony, db_shares, passwords, raw_shares, fingerprint, is_root, cert_der, cert_pem, csr_pem, subject_dn)

              error ->
                fail_ceremony(ceremony.id, "shamir_split_failed")
                error
            end

          error ->
            fail_ceremony(ceremony.id, "cert_generation_failed")
            error
        end

      error ->
        fail_ceremony(ceremony.id, "keygen_failed")
        error
    end
  end

  defp encrypt_and_commit(ceremony, db_shares, passwords, raw_shares, fingerprint, is_root, cert_der, cert_pem, csr_pem, subject_dn) do
    encrypt_result =
      Enum.zip(db_shares, raw_shares)
      |> Enum.reduce_while({:ok, []}, fn {db_share, raw_share}, {:ok, acc} ->
        case Map.fetch(passwords, db_share.custodian_name) do
          {:ok, password} ->
            case ShareEncryption.encrypt_share(raw_share, password) do
              {:ok, encrypted} -> {:cont, {:ok, [{db_share, encrypted} | acc]}}
              {:error, reason} -> {:halt, {:error, {:share_encryption_failed, reason}}}
            end
          :error ->
            {:halt, {:error, {:missing_password, db_share.custodian_name}}}
        end
      end)

    case encrypt_result do
      {:error, reason} ->
        fail_ceremony(ceremony.id, "share_encryption_failed")
        {:error, reason}

      {:ok, encrypted_pairs_reversed} ->
        encrypted_pairs = Enum.reverse(encrypted_pairs_reversed)

        case Repo.transaction(fn ->
          # Update shares with encrypted data
          Enum.each(encrypted_pairs, fn {db_share, encrypted_share} ->
            updated = %{db_share | encrypted_share: encrypted_share, updated_at: DateTime.utc_now() |> DateTime.truncate(:second)}
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(ThresholdShare), updated))
          end)

          # Activate issuer key if root CA
          if is_root and cert_der do
            case :mnesia.read(PkiMnesia.Schema.table_name(IssuerKey), ceremony.issuer_key_id) do
              [record] ->
                key = Repo.record_to_struct(IssuerKey, record)
                activated = %{key |
                  status: "active",
                  certificate_der: cert_der,
                  certificate_pem: cert_pem,
                  fingerprint: fingerprint,
                  subject_dn: subject_dn,
                  updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
                }
                :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(IssuerKey), activated))
              [] -> :ok
            end
          end

          # Update ceremony to completed
          case :mnesia.read(PkiMnesia.Schema.table_name(KeyCeremony), ceremony.id) do
            [record] ->
              c = Repo.record_to_struct(KeyCeremony, record)
              completed = %{c |
                status: "completed",
                domain_info: Map.merge(c.domain_info || %{}, %{
                  "fingerprint" => fingerprint,
                  "csr_pem" => csr_pem,
                  "subject_dn" => subject_dn
                }),
                updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
              }
              :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(KeyCeremony), completed))
            [] -> :ok
          end

          append_transcript_in_tx(ceremony.id, "system", "ceremony_completed", %{fingerprint: fingerprint})
        end) do
          {:ok, _} ->
            :erlang.garbage_collect()

            # Auto-offline root CA after ceremony
            case Repo.get(PkiMnesia.Structs.CaInstance, ceremony.ca_instance_id) do
              {:ok, ca} when not is_nil(ca) ->
                if CaInstanceManagement.is_root?(ca) do
                  CaInstanceManagement.set_offline(ceremony.ca_instance_id)
                end
              _ -> :ok
            end

            {:ok, %{fingerprint: fingerprint, csr_pem: csr_pem}}

          {:error, reason} ->
            fail_ceremony(ceremony.id, "transaction_failed: #{inspect(reason)}")
            {:error, reason}
        end
    end
  end

  # Appends a transcript entry inside an already-open :mnesia.transaction context.
  # Safe to call from within Repo.transaction/1 or bare :mnesia.transaction/1 fns.
  defp append_transcript_in_tx(ceremony_id, actor, action, details) do
    table = PkiMnesia.Schema.table_name(CeremonyTranscript)
    case :mnesia.index_read(table, ceremony_id, :ceremony_id) do
      [record | _] ->
        transcript = Repo.record_to_struct(CeremonyTranscript, record)
        entry = %{
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          actor: actor,
          action: action,
          details: details
        }
        updated = %{transcript | entries: (transcript.entries || []) ++ [entry]}
        :mnesia.write(Repo.struct_to_record(table, updated))
      [] -> :ok
    end
  end


  defp validate_threshold(k, n) when is_integer(k) and is_integer(n) and k >= 2 and k <= n, do: :ok
  defp validate_threshold(_, _), do: {:error, :invalid_threshold}

  defp validate_participants(names, n) when is_list(names) and length(names) == n, do: :ok
  defp validate_participants(_, _), do: {:error, :participant_count_mismatch}

  defp validate_ceremony_mode(%{is_root: true, ceremony_mode: :simplified}),
    do: {:error, :root_ca_requires_full_ceremony}
  defp validate_ceremony_mode(_), do: :ok

  defp generate_self_signed(algorithm, private_key, public_key, subject_dn) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        case PkiCrypto.X509Builder.self_sign(algorithm, %{public_key: public_key, private_key: private_key}, subject_dn, 365 * 25) do
          {:ok, cert_der} ->
            cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
            {:ok, cert_der, cert_pem}
          {:error, _} = error -> error
        end

      {:ok, %{family: _classical}} ->
        try do
          native_key = decode_private_key(private_key)
          root_cert = X509.Certificate.self_signed(native_key, subject_dn, template: :root_ca, hash: :sha256, serial: {:random, 8}, validity: 365 * 25)
          cert_der = X509.Certificate.to_der(root_cert)
          cert_pem = X509.Certificate.to_pem(root_cert)
          {:ok, cert_der, cert_pem}
        rescue
          e -> {:error, e}
        end

      :error -> {:error, {:unknown_algorithm, algorithm}}
    end
  end

  defp generate_csr(algorithm, private_key, public_key, subject_dn) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        PkiCrypto.Csr.generate(algorithm, %{public_key: public_key, private_key: private_key}, subject_dn)

      {:ok, %{family: _classical}} ->
        try do
          native_key = decode_private_key(private_key)
          PkiCrypto.Csr.generate(algorithm, native_key, subject_dn)
        rescue
          e -> {:error, e}
        end

      :error -> {:error, {:unknown_algorithm, algorithm}}
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
