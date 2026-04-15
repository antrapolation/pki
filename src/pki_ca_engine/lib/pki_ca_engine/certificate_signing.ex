defmodule PkiCaEngine.CertificateSigning do
  @moduledoc """
  Certificate Signing Pipeline.

  RA sends approved CSR + cert profile -> CA verifies key active ->
  applies profile -> signs -> stores -> returns cert.
  """

  alias PkiCaEngine.{KeyActivation, ValidationNotifier, TenantRepo}
  alias PkiCaEngine.Schema.{IssuedCertificate, IssuerKey}
  import Ecto.Query
  import PkiCaEngine.QueryHelpers

  require Logger

  @doc """
  Signs a certificate using the given issuer key.

  Verifies the key is active via KeyActivation, builds a real X.509 certificate
  signed by the issuer's private key, and stores the result.

  Options:
    - `:activation_server` - the KeyActivation server to use (default: KeyActivation)
  """
  def sign_certificate(tenant_id, issuer_key_id, csr_pem, cert_profile_map, opts \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)
    activation_server = opts[:activation_server] || KeyActivation

    csr_fingerprint = compute_csr_fingerprint(csr_pem)

    with {:ok, issuer_key_record} <- get_issuer_key(repo, issuer_key_id),
         :ok <- check_key_status(issuer_key_record),
         :ok <- check_duplicate_csr(repo, issuer_key_id, csr_fingerprint),
         :ok <- check_ca_online(repo, issuer_key_record),
         :ok <- check_leaf_ca(tenant_id, repo, issuer_key_record),
         {:ok, private_key_der} <- KeyActivation.get_active_key(activation_server, issuer_key_id) do
      serial = generate_serial()
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      validity_days = Map.get(cert_profile_map, :validity_days, 365)
      not_after = NaiveDateTime.add(DateTime.to_naive(now), validity_days * 86400, :second)
                  |> DateTime.from_naive!("Etc/UTC")

      subject_dn = Map.get(cert_profile_map, :subject_dn, extract_subject_from_csr(csr_pem))

      case do_sign(issuer_key_record, private_key_der, csr_pem, subject_dn, validity_days, serial) do
        {:ok, cert_der, cert_pem_str} ->
          result =
            %IssuedCertificate{}
            |> IssuedCertificate.changeset(%{
              serial_number: serial,
              issuer_key_id: issuer_key_id,
              subject_dn: subject_dn,
              cert_der: cert_der,
              cert_pem: cert_pem_str,
              not_before: now,
              not_after: not_after,
              cert_profile_id: cert_profile_map[:id],
              csr_fingerprint: csr_fingerprint
            })
            |> repo.insert()

          case result do
            {:ok, cert} ->
              prefix = Process.get(:pki_ecto_prefix)
              Task.start(fn ->
                if prefix, do: Process.put(:pki_ecto_prefix, prefix)
                ValidationNotifier.notify_issuance(cert)
              end)
              {:ok, cert}

            error ->
              error
          end

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :not_active} -> {:error, :key_not_active}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Revokes a certificate by serial number with a given reason.
  """
  def revoke_certificate(tenant_id, serial_number, reason) do
    repo = TenantRepo.ca_repo(tenant_id)

    case get_certificate(tenant_id, serial_number) do
      {:ok, %{status: "revoked"}} ->
        {:error, :already_revoked}

      {:ok, cert} ->
        result =
          cert
          |> Ecto.Changeset.change(
            status: "revoked",
            revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
            revocation_reason: reason
          )
          |> repo.update()

        case result do
          {:ok, revoked_cert} ->
            prefix = Process.get(:pki_ecto_prefix)
            Task.start(fn ->
              if prefix, do: Process.put(:pki_ecto_prefix, prefix)
              ValidationNotifier.notify_revocation(serial_number, reason)
            end)
            {:ok, revoked_cert}

          error ->
            error
        end

      error ->
        error
    end
  end

  @doc """
  Retrieves a certificate by serial number.
  """
  def get_certificate(tenant_id, serial_number) do
    repo = TenantRepo.ca_repo(tenant_id)
    case repo.one(from c in IssuedCertificate, where: c.serial_number == ^serial_number) do
      nil -> {:error, :not_found}
      cert -> {:ok, cert}
    end
  end

  @doc """
  Lists certificates for an issuer key, with optional filters.

  Filters:
    - `{:status, status}` - filter by status ("active" or "revoked")
  """
  def list_certificates(tenant_id, issuer_key_id, filters \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)
    limit = Keyword.get(filters, :limit, 100)
    offset = Keyword.get(filters, :offset, 0)
    clean_filters = Keyword.drop(filters, [:limit, :offset])

    IssuedCertificate
    |> where([c], c.issuer_key_id == ^issuer_key_id)
    |> apply_eq_filters(clean_filters)
    |> order_by(desc: :inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> repo.all()
  end

  def list_certificates_by_ca(tenant_id, ca_instance_id, filters \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)
    limit = Keyword.get(filters, :limit, 100)
    offset = Keyword.get(filters, :offset, 0)
    clean_filters = Keyword.drop(filters, [:limit, :offset])

    IssuedCertificate
    |> join(:inner, [c], k in PkiCaEngine.Schema.IssuerKey, on: c.issuer_key_id == k.id)
    |> where([c, k], k.ca_instance_id == ^ca_instance_id)
    |> apply_eq_filters(clean_filters)
    |> order_by(desc: :inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> repo.all()
  end

  def count_certificates(tenant_id, issuer_key_id, filters \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)

    IssuedCertificate
    |> where([c], c.issuer_key_id == ^issuer_key_id)
    |> apply_eq_filters(filters)
    |> repo.aggregate(:count)
  end

  # -- Private --

  defp do_sign(issuer_key_record, private_key_der, csr_pem, subject_dn, validity_days, serial) do
    issuer_alg_id = issuer_key_record.algorithm
    issuer_cert_der = issuer_key_record.certificate_der
    serial_int = hex_serial_to_integer(serial)

    cond do
      issuer_cert_der == nil ->
        Logger.error(
          "Cannot sign: issuer key #{issuer_key_record.id} has no certificate (ceremony not completed?)"
        )

        {:error, :issuer_certificate_not_available}

      true ->
        issuer_key = decode_issuer_key(issuer_alg_id, private_key_der)

        with {:ok, csr} <- PkiCrypto.Csr.parse(csr_pem),
             :ok <- PkiCrypto.Csr.verify_pop(csr),
             {:ok, tbs, _sig_alg_oid} <-
               PkiCrypto.X509Builder.build_tbs_cert(
                 csr,
                 %{cert_der: issuer_cert_der, algorithm_id: issuer_alg_id},
                 subject_dn,
                 validity_days,
                 serial_int
               ),
             {:ok, cert_der} <- PkiCrypto.X509Builder.sign_tbs(tbs, issuer_alg_id, issuer_key) do
          cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
          {:ok, cert_der, cert_pem}
        else
          {:error, reason} ->
            Logger.error("Certificate signing failed: #{inspect(reason)}")
            {:error, {:signing_failed, reason}}
        end
    end
  end

  # Decode at-rest private key bytes into the form the signer expects.
  # Classical: :public_key record. PQC: raw bytes (pass-through).
  defp decode_issuer_key(algorithm_id, der) when algorithm_id in ["ECC-P256", "ECC-P384"] do
    :public_key.der_decode(:ECPrivateKey, der)
  end

  defp decode_issuer_key(algorithm_id, der) when algorithm_id in ["RSA-2048", "RSA-4096"] do
    :public_key.der_decode(:RSAPrivateKey, der)
  end

  defp decode_issuer_key(algorithm_id, bytes) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm_id) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] -> bytes
      _ -> raise "unknown issuer algorithm: #{algorithm_id}"
    end
  end

  defp generate_serial do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp hex_serial_to_integer(hex) do
    {int, _} = Integer.parse(hex, 16)
    int
  end

  defp extract_subject_from_csr(csr_pem) when is_binary(csr_pem) do
    case X509.CSR.from_pem(csr_pem) do
      {:ok, csr} ->
        X509.RDNSequence.to_string(X509.CSR.subject(csr))

      _ ->
        "CN=unknown"
    end
  rescue
    _ -> "CN=unknown"
  end

  defp extract_subject_from_csr(_), do: "CN=unknown"

  defp compute_csr_fingerprint(csr_pem) when is_binary(csr_pem) do
    case X509.CSR.from_pem(csr_pem) do
      {:ok, csr} ->
        csr
        |> X509.CSR.to_der()
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)

      _ ->
        # Fallback: hash raw PEM if it can't be parsed as X.509
        :crypto.hash(:sha256, csr_pem) |> Base.encode16(case: :lower)
    end
  rescue
    _ -> :crypto.hash(:sha256, csr_pem) |> Base.encode16(case: :lower)
  end

  defp compute_csr_fingerprint(_), do: nil

  defp check_duplicate_csr(_repo, _issuer_key_id, nil), do: :ok

  defp check_duplicate_csr(repo, issuer_key_id, csr_fingerprint) do
    existing =
      repo.one(
        from c in IssuedCertificate,
          where: c.issuer_key_id == ^issuer_key_id and
                 c.csr_fingerprint == ^csr_fingerprint and
                 c.status == "active",
          limit: 1
      )

    case existing do
      nil -> :ok
      _cert -> {:error, :duplicate_csr}
    end
  end

  defp check_key_status(%{status: "active"}), do: :ok
  defp check_key_status(%{status: status}) do
    Logger.warning("Signing rejected: issuer key status is #{status}, must be active")
    {:error, :key_not_active}
  end

  defp check_ca_online(_repo, %{ca_instance_id: nil}), do: :ok

  defp check_ca_online(repo, %{ca_instance_id: ca_id}) do
    case repo.get(PkiCaEngine.Schema.CaInstance, ca_id) do
      nil -> {:error, :ca_instance_not_found}
      %{is_offline: true} -> {:error, :ca_offline}
      _ -> :ok
    end
  end

  defp check_leaf_ca(_tenant_id, _repo, %{ca_instance_id: nil}), do: :ok

  defp check_leaf_ca(tenant_id, repo, %{ca_instance_id: ca_id}) do
    case repo.get(PkiCaEngine.Schema.CaInstance, ca_id) do
      nil -> {:error, :ca_instance_not_found}
      ca ->
        if PkiCaEngine.CaInstanceManagement.is_leaf?(tenant_id, ca),
          do: :ok,
          else: {:error, :non_leaf_ca_cannot_issue}
    end
  end

  defp get_issuer_key(repo, issuer_key_id) do
    case repo.get(IssuerKey, issuer_key_id) do
      nil -> {:error, :issuer_key_not_found}
      key -> {:ok, key}
    end
  end
end
