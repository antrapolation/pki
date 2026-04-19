defmodule PkiCaEngine.CertificateSigning do
  @moduledoc """
  Certificate Signing Pipeline against Mnesia.

  Signing path:
    CSR PEM -> PkiCrypto.Csr.parse -> PkiCrypto.X509Builder.build_tbs_cert
    -> PkiCrypto.X509Builder.sign_tbs -> cert DER

  PkiCrypto is UNCHANGED. This module only handles storage + orchestration.
  """

  alias PkiCaEngine.{KeyActivation, CaInstanceManagement, KeyStore.SoftwareAdapter}
  alias PkiCaEngine.KeyStore.Dispatcher
  alias PkiMnesia.{Repo, Structs}
  alias Structs.{IssuedCertificate, IssuerKey, CertificateStatus}

  require Logger

  def sign_certificate(issuer_key_id, csr_pem, cert_profile_map, opts \\ []) do
    csr_fingerprint = compute_csr_fingerprint(csr_pem)

    with {:ok, issuer_key} <- get_issuer_key(issuer_key_id),
         :ok <- check_key_status(issuer_key),
         :ok <- check_duplicate_csr(issuer_key_id, csr_fingerprint),
         :ok <- check_ca_online(issuer_key),
         :ok <- check_leaf_ca(issuer_key) do

      serial = generate_serial()
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      validity_days = Map.get(cert_profile_map, :validity_days, 365)
      not_after = DateTime.add(now, validity_days * 86400, :second) |> DateTime.truncate(:second)
      subject_dn = Map.get(cert_profile_map, :subject_dn, extract_subject_from_csr(csr_pem))

      sign_result =
        case issuer_key.keystore_type do
          :software ->
            # Software path: get raw key from KeyActivation, sign in-process via X509Builder.
            # activation_server opt is forwarded for test isolation.
            activation_server = opts[:activation_server] || KeyActivation
            case SoftwareAdapter.get_raw_key(issuer_key_id, activation_server: activation_server) do
              {:ok, private_key_der} ->
                do_sign(issuer_key, private_key_der, csr_pem, subject_dn, validity_days, serial)
              {:error, _} = err -> err
            end

          _hsm_type ->
            # HSM path: build TBS, sign via Dispatcher, assemble certificate
            do_sign_via_dispatcher(issuer_key, issuer_key_id, csr_pem, subject_dn, validity_days, serial)
        end

      case sign_result do
        {:ok, cert_der, cert_pem_str} ->
          cert = IssuedCertificate.new(%{
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

          case Repo.insert(cert) do
            {:ok, cert} ->
              # Also create certificate_status record for OCSP/CRL
              cert_status = CertificateStatus.new(%{
                serial_number: serial,
                issuer_key_id: issuer_key_id,
                status: "active",
                not_after: not_after
              })
              Repo.insert(cert_status)

              {:ok, cert}

            error -> error
          end

        {:error, :not_active} -> {:error, :key_not_active}
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def revoke_certificate(serial_number, reason) do
    case Repo.where(IssuedCertificate, fn c -> c.serial_number == serial_number end) do
      {:ok, []} -> {:error, :not_found}
      {:ok, [%{status: "revoked"} | _]} -> {:error, :already_revoked}
      {:ok, [cert | _]} ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)
        with {:ok, revoked} <- Repo.update(cert, %{
               status: "revoked",
               revoked_at: now,
               revocation_reason: reason,
               updated_at: now
             }) do
          # Update certificate_status for OCSP/CRL
          case Repo.where(CertificateStatus, fn s -> s.serial_number == serial_number end) do
            {:ok, [status | _]} ->
              Repo.update(status, %{status: "revoked", revoked_at: now, revocation_reason: reason, updated_at: now})
            _ -> :ok
          end
          {:ok, revoked}
        end
      {:error, _} = err -> err
    end
  end

  def get_certificate(serial_number) do
    case Repo.where(IssuedCertificate, fn c -> c.serial_number == serial_number end) do
      {:ok, []} -> {:error, :not_found}
      {:ok, [cert | _]} -> {:ok, cert}
      {:error, _} = err -> err
    end
  end

  def list_certificates(issuer_key_id, filters \\ []) do
    status_filter = Keyword.get(filters, :status)

    Repo.where(IssuedCertificate, fn c ->
      c.issuer_key_id == issuer_key_id and
      (status_filter == nil or c.status == status_filter)
    end)
  end

  # -- Private: signing logic (unchanged crypto path) --

  defp do_sign(issuer_key, private_key_der, csr_pem, subject_dn, validity_days, serial) do
    issuer_alg_id = issuer_key.algorithm
    issuer_cert_der = issuer_key.certificate_der
    serial_int = hex_serial_to_integer(serial)

    if issuer_cert_der == nil do
      {:error, :issuer_certificate_not_available}
    else
      issuer_key_decoded = decode_issuer_key(issuer_alg_id, private_key_der)

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
           {:ok, cert_der} <- PkiCrypto.X509Builder.sign_tbs(tbs, issuer_alg_id, issuer_key_decoded) do
        cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
        {:ok, cert_der, cert_pem}
      else
        {:error, reason} ->
          Logger.error("Certificate signing failed: #{inspect(reason)}")
          {:error, {:signing_failed, reason}}
      end
    end
  end

  defp do_sign_via_dispatcher(issuer_key, issuer_key_id, csr_pem, subject_dn, validity_days, serial) do
    issuer_cert_der = issuer_key.certificate_der
    issuer_alg_id = issuer_key.algorithm
    serial_int = hex_serial_to_integer(serial)

    if issuer_cert_der == nil do
      {:error, :issuer_certificate_not_available}
    else
      with {:ok, csr} <- PkiCrypto.Csr.parse(csr_pem),
           :ok <- PkiCrypto.Csr.verify_pop(csr),
           {:ok, tbs_der, sig_alg_oid} <-
             PkiCrypto.X509Builder.build_tbs_cert(
               csr,
               %{cert_der: issuer_cert_der, algorithm_id: issuer_alg_id},
               subject_dn,
               validity_days,
               serial_int
             ),
           {:ok, signature} <- Dispatcher.sign(issuer_key_id, tbs_der) do
        cert_der = PkiCrypto.X509Builder.assemble_cert(tbs_der, sig_alg_oid, signature)
        cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
        {:ok, cert_der, cert_pem}
      else
        {:error, reason} ->
          Logger.error("Certificate signing via HSM failed: #{inspect(reason)}")
          {:error, {:signing_failed, reason}}
      end
    end
  end

  defp decode_issuer_key(alg_id, der) when alg_id in ["ECC-P256", "ECC-P384"],
    do: :public_key.der_decode(:ECPrivateKey, der)
  defp decode_issuer_key(alg_id, der) when alg_id in ["RSA-2048", "RSA-4096"],
    do: :public_key.der_decode(:RSAPrivateKey, der)
  defp decode_issuer_key(_alg_id, bytes), do: bytes

  defp generate_serial, do: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

  defp hex_serial_to_integer(hex) do
    {int, _} = Integer.parse(hex, 16)
    int
  end

  defp extract_subject_from_csr(csr_pem) when is_binary(csr_pem) do
    case X509.CSR.from_pem(csr_pem) do
      {:ok, csr} -> X509.RDNSequence.to_string(X509.CSR.subject(csr))
      _ -> "CN=unknown"
    end
  rescue
    _ -> "CN=unknown"
  end
  defp extract_subject_from_csr(_), do: "CN=unknown"

  defp compute_csr_fingerprint(csr_pem) when is_binary(csr_pem) do
    :crypto.hash(:sha256, csr_pem) |> Base.encode16(case: :lower)
  end
  defp compute_csr_fingerprint(_), do: nil

  defp check_duplicate_csr(_issuer_key_id, nil), do: :ok
  defp check_duplicate_csr(issuer_key_id, csr_fingerprint) do
    case Repo.where(IssuedCertificate, fn c ->
      c.issuer_key_id == issuer_key_id and c.csr_fingerprint == csr_fingerprint and c.status == "active"
    end) do
      {:ok, []} -> :ok
      {:ok, _existing} -> {:error, :duplicate_csr}
      {:error, _} = err -> err
    end
  end

  defp check_key_status(%{status: "active"}), do: :ok
  defp check_key_status(_), do: {:error, :key_not_active}

  defp check_ca_online(%{ca_instance_id: nil}), do: :ok
  defp check_ca_online(%{ca_instance_id: ca_id}) do
    case Repo.get(PkiMnesia.Structs.CaInstance, ca_id) do
      {:ok, nil} -> {:error, :ca_instance_not_found}
      {:ok, %{is_offline: true}} -> {:error, :ca_offline}
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  defp check_leaf_ca(%{ca_instance_id: nil}), do: :ok
  defp check_leaf_ca(%{ca_instance_id: ca_id}) do
    case Repo.get(PkiMnesia.Structs.CaInstance, ca_id) do
      {:ok, nil} -> {:error, :ca_instance_not_found}
      {:ok, ca} -> if CaInstanceManagement.is_leaf?(ca), do: :ok, else: {:error, :non_leaf_ca_cannot_issue}
      {:error, _} = err -> err
    end
  end

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end
end
