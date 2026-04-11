defmodule PkiCaEngine.KeyCeremony.SyncCeremony do
  @moduledoc """
  Synchronous key ceremony -- all custodians present simultaneously.

  Orchestrates the full ceremony flow:
  1. `initiate/3` - creates ceremony + issuer_key records
  2. `generate_keypair/1` - generates keypair via PkiCrypto.Algorithm protocol
  3. `distribute_shares/4` - splits private key, encrypts shares, stores in DB
  4. `complete_as_root/4` - for independent root CA (activates key with cert)
  5. `complete_as_sub_ca/4` - for sub-CA (key stays pending, generates real PKCS#10 CSR)

  Private key material is NEVER persisted to DB -- only encrypted shares are stored.
  """

  require Logger

  alias PkiCaEngine.TenantRepo
  alias PkiCaEngine.Schema.{CaInstance, KeyCeremony, IssuerKey, ThresholdShare}
  alias PkiCaEngine.{CaInstanceManagement, KeystoreManagement, IssuerKeyManagement}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  @doc """
  Initiates a synchronous key ceremony.

  Creates a KeyCeremony record and an associated IssuerKey record (status: "pending").

  ## Parameters
    - `ca_instance_id` - the CA instance ID
    - `params` - map with keys: `:algorithm`, `:keystore_id`, `:threshold_k`,
      `:threshold_n`, `:initiated_by`, and optionally `:domain_info`, `:key_alias`, `:is_root`

  ## Returns
    - `{:ok, {ceremony, issuer_key}}` on success
    - `{:error, :invalid_threshold}` if k < 2 or k > n
    - `{:error, :not_found}` if keystore does not exist
  """
  @spec initiate(String.t(), String.t(), map()) :: {:ok, {KeyCeremony.t(), IssuerKey.t()}} | {:error, term()}
  def initiate(tenant_id, ca_instance_id, params) do
    repo = TenantRepo.ca_repo(tenant_id)

    with :ok <- validate_threshold(params.threshold_k, params.threshold_n),
         {:ok, _keystore} <- KeystoreManagement.get_keystore(tenant_id, params.keystore_id) do
      repo.transaction(fn ->
        case IssuerKeyManagement.create_issuer_key(tenant_id, ca_instance_id, %{
               key_alias: Map.get(params, :key_alias) || "root-#{System.unique_integer([:positive])}",
               algorithm: params.algorithm,
               is_root: Map.get(params, :is_root, true),
               threshold_config: %{k: params.threshold_k, n: params.threshold_n}
             }) do
          {:ok, issuer_key} ->
            case %KeyCeremony{}
                 |> KeyCeremony.changeset(%{
                   ca_instance_id: ca_instance_id,
                   issuer_key_id: issuer_key.id,
                   ceremony_type: "sync",
                   algorithm: params.algorithm,
                   keystore_id: params.keystore_id,
                   threshold_k: params.threshold_k,
                   threshold_n: params.threshold_n,
                   domain_info: Map.get(params, :domain_info, %{}),
                   initiated_by: params.initiated_by
                 })
                 |> repo.insert() do
              {:ok, ceremony} ->
                {ceremony, issuer_key}

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
  Generates a keypair for the given algorithm string via PkiCrypto.

  Returns `{:ok, %{public_key: binary, private_key: binary}}`.
  The private key material is returned in memory only -- it must NOT be persisted to DB.
  """
  @spec generate_keypair(String.t()) :: {:ok, map()} | {:error, term()}
  def generate_keypair(algorithm) do
    case PkiCrypto.Registry.get(algorithm) do
      nil -> {:error, {:unsupported_algorithm, algorithm}}
      algo_struct -> PkiCrypto.Algorithm.generate_keypair(algo_struct)
    end
  end

  @doc """
  Distributes private key shares to custodians.

  Splits the private key into N shares using PkiCrypto.Shamir, encrypts each share
  with the corresponding custodian's password, and stores encrypted shares in the DB.

  ## Parameters
    - `ceremony` - the KeyCeremony record (must have threshold_n, threshold_k, issuer_key_id)
    - `private_key_material` - the raw private key binary (NOT stored in DB)
    - `custodian_passwords` - list of `{custodian_user_id, password}` tuples

  ## Returns
    - `{:ok, share_count}` on success
    - `{:error, :wrong_custodian_count}` if custodian count != threshold_n
  """
  @spec distribute_shares(String.t(), KeyCeremony.t(), binary(), [{String.t(), String.t()}]) ::
          {:ok, integer()} | {:error, term()}
  def distribute_shares(tenant_id, ceremony, private_key_material, custodian_passwords) do
    repo = TenantRepo.ca_repo(tenant_id)
    n = length(custodian_passwords)

    if n != ceremony.threshold_n do
      {:error, :wrong_custodian_count}
    else
      case PkiCrypto.Shamir.split(private_key_material, ceremony.threshold_k, n) do
        {:ok, shares} ->
          repo.transaction(fn ->
            Enum.zip(custodian_passwords, shares)
            |> Enum.with_index(1)
            |> Enum.each(fn {{{user_id, password}, share}, index} ->
              case ShareEncryption.encrypt_share(share, password) do
                {:ok, encrypted} ->
                  case %ThresholdShare{}
                       |> ThresholdShare.changeset(%{
                         issuer_key_id: ceremony.issuer_key_id,
                         custodian_user_id: user_id,
                         share_index: index,
                         encrypted_share: encrypted,
                         min_shares: ceremony.threshold_k,
                         total_shares: n
                       })
                       |> repo.insert() do
                    {:ok, _} -> :ok
                    {:error, reason} -> repo.rollback(reason)
                  end

                {:error, reason} ->
                  repo.rollback({:encryption_failed, reason})
              end
            end)

            n
          end)

        {:error, reason} ->
          {:error, {:share_split_failed, reason}}
      end
    end
  end

  @doc """
  Completes a ceremony for an independent root CA.

  Activates the issuer key with the provided certificate and marks the ceremony completed.

  ## Returns
    - `{:ok, updated_ceremony}` on success
  """
  @spec complete_as_root(String.t(), KeyCeremony.t(), binary(), String.t()) ::
          {:ok, KeyCeremony.t()} | {:error, term()}
  def complete_as_root(tenant_id, ceremony, cert_der, cert_pem) do
    repo = TenantRepo.ca_repo(tenant_id)

    result =
      repo.transaction(fn ->
        case repo.get(IssuerKey, ceremony.issuer_key_id) do
          nil ->
            repo.rollback(:issuer_key_not_found)

          issuer_key ->
            case IssuerKeyManagement.activate_by_certificate(tenant_id, issuer_key, %{
                   certificate_der: cert_der,
                   certificate_pem: cert_pem
                 }) do
              {:ok, _key} ->
                case ceremony
                     |> Ecto.Changeset.change(status: "completed")
                     |> repo.update() do
                  {:ok, updated} -> updated
                  {:error, reason} -> repo.rollback({:operation_failed, reason})
                end

              {:error, reason} ->
                repo.rollback({:operation_failed, reason})
            end
        end
      end)

    # Auto-offline root CA after successful ceremony completion
    case result do
      {:ok, _} ->
        ca = repo.get(CaInstance, ceremony.ca_instance_id)
        if ca && CaInstanceManagement.is_root?(ca) do
          case CaInstanceManagement.set_offline(tenant_id, ceremony.ca_instance_id) do
            {:ok, _} -> :ok
            {:error, reason} ->
              Logger.error("[auto_offline] Failed to take root CA #{ceremony.ca_instance_id} offline after ceremony: #{inspect(reason)}")
          end
        end

      _ ->
        :ok
    end

    result
  end

  @doc """
  Completes a ceremony for a sub-CA.

  Marks the ceremony completed but the issuer key stays "pending" (awaiting external CA signing).
  Generates a PKCS#10 CSR signed by the ceremony's private key, to be sent to the parent CA.

  ## Parameters
    - `ceremony` - the KeyCeremony record (must have domain_info with subject DN)
    - `private_key` - the raw private key (Erlang key term or binary); must be the key
      generated during the ceremony's `generate_keypair` step. The caller is responsible
      for passing this in-memory value since private keys are never persisted.
    - `opts` - optional keyword list:
      - `:subject` - subject DN string (e.g., "/CN=Sub-CA/O=Org"); defaults to
        `ceremony.domain_info["subject_dn"]` or a generated default

  ## Returns
    - `{:ok, {updated_ceremony, csr_pem}}` on success
    - `{:error, term()}` on failure
  """
  @spec complete_as_sub_ca(String.t(), KeyCeremony.t(), term(), keyword()) ::
          {:ok, {KeyCeremony.t(), String.t()}} | {:error, term()}
  def complete_as_sub_ca(tenant_id, ceremony, private_key, opts \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)

    subject =
      Keyword.get(opts, :subject) ||
        get_in(ceremony.domain_info, ["subject_dn"]) ||
        "/CN=Sub-CA-#{ceremony.ca_instance_id}"

    repo.transaction(fn ->
      case ceremony
           |> Ecto.Changeset.change(status: "completed")
           |> repo.update() do
        {:ok, updated} ->
          csr_pem = generate_csr(private_key, subject)
          {updated, csr_pem}

        {:error, reason} ->
          repo.rollback({:operation_failed, reason})
      end
    end)
  end

  defp generate_csr(private_key, subject) do
    csr = X509.CSR.new(private_key, subject)
    X509.CSR.to_pem(csr)
  end

  defp validate_threshold(k, n) when is_integer(k) and is_integer(n) and k >= 2 and k <= n,
    do: :ok

  defp validate_threshold(_, _), do: {:error, :invalid_threshold}
end
