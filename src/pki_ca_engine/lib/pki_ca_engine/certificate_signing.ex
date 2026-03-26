defmodule PkiCaEngine.CertificateSigning do
  @moduledoc """
  Certificate Signing Pipeline.

  RA sends approved CSR + cert profile -> CA verifies key active ->
  applies profile -> signs -> stores -> returns cert.
  """

  alias PkiCaEngine.{Repo, KeyActivation, ValidationNotifier}
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
  def sign_certificate(issuer_key_id, csr_pem, cert_profile_map, opts \\ []) do
    activation_server = opts[:activation_server] || KeyActivation

    with {:ok, private_key_der} <- KeyActivation.get_active_key(activation_server, issuer_key_id),
         {:ok, issuer_key_record} <- get_issuer_key(issuer_key_id) do
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
              cert_profile_id: cert_profile_map[:id]
            })
            |> Repo.insert()

          case result do
            {:ok, cert} ->
              Task.start(fn -> ValidationNotifier.notify_issuance(cert) end)
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
  def revoke_certificate(serial_number, reason) do
    case get_certificate(serial_number) do
      {:ok, cert} ->
        result =
          cert
          |> Ecto.Changeset.change(
            status: "revoked",
            revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
            revocation_reason: reason
          )
          |> Repo.update()

        case result do
          {:ok, revoked_cert} ->
            Task.start(fn -> ValidationNotifier.notify_revocation(serial_number, reason) end)
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
  def get_certificate(serial_number) do
    case Repo.one(from c in IssuedCertificate, where: c.serial_number == ^serial_number) do
      nil -> {:error, :not_found}
      cert -> {:ok, cert}
    end
  end

  @doc """
  Lists certificates for an issuer key, with optional filters.

  Filters:
    - `{:status, status}` - filter by status ("active" or "revoked")
  """
  def list_certificates(issuer_key_id, filters \\ []) do
    IssuedCertificate
    |> where([c], c.issuer_key_id == ^issuer_key_id)
    |> apply_eq_filters(filters)
    |> order_by(asc: :inserted_at)
    |> Repo.all()
  end

  # -- Private --

  defp do_sign(issuer_key_record, private_key_der, csr_pem, subject_dn, validity_days, serial) do
    algorithm = issuer_key_record.algorithm

    with {:ok, native_private_key} <- decode_private_key(private_key_der, algorithm) do
      serial_int = hex_serial_to_integer(serial)

      case issuer_key_record.certificate_der do
        nil ->
          # Self-signed: no issuer cert available
          sign_self_signed(native_private_key, csr_pem, subject_dn, validity_days, serial_int)

        issuer_cert_der when is_binary(issuer_cert_der) ->
          issuer_cert = X509.Certificate.from_der!(issuer_cert_der)
          sign_with_issuer(native_private_key, issuer_cert, csr_pem, subject_dn, validity_days, serial_int)
      end
    end
  end

  defp sign_with_issuer(issuer_key, issuer_cert, csr_pem, subject_dn, validity_days, serial) do
    case extract_public_key_from_csr(csr_pem) do
      nil ->
        Logger.error("Cannot issue certificate: CSR is invalid or missing public key")
        {:error, :invalid_csr_no_public_key}

      public_key ->
        do_sign_with_issuer(issuer_key, issuer_cert, public_key, subject_dn, validity_days, serial)
    end
  end

  defp do_sign_with_issuer(issuer_key, issuer_cert, public_key, subject_dn, validity_days, serial) do
    cert =
      X509.Certificate.new(
        public_key,
        subject_dn,
        issuer_cert,
        issuer_key,
        serial: serial,
        hash: :sha256,
        validity: validity_days,
        extensions: [
          basic_constraints: X509.Certificate.Extension.basic_constraints(false),
          key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyEncipherment]),
          subject_key_identifier: true,
          authority_key_identifier: true
        ]
      )

    cert_der = X509.Certificate.to_der(cert)
    cert_pem_str = X509.Certificate.to_pem(cert)
    {:ok, cert_der, cert_pem_str}
  rescue
    e ->
      Logger.error("Certificate signing failed: #{inspect(e)}")
      {:error, {:signing_failed, e}}
  end

  defp sign_self_signed(private_key, _csr_pem, subject_dn, validity_days, serial) do
    # For self-signed subscriber certs (no issuer cert available)
    cert =
      X509.Certificate.self_signed(
        private_key,
        subject_dn,
        serial: serial,
        hash: :sha256,
        validity: validity_days,
        extensions: [
          basic_constraints: X509.Certificate.Extension.basic_constraints(false),
          key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyEncipherment]),
          subject_key_identifier: true
        ]
      )

    cert_der = X509.Certificate.to_der(cert)
    cert_pem_str = X509.Certificate.to_pem(cert)
    {:ok, cert_der, cert_pem_str}
  rescue
    e ->
      Logger.error("Self-signed certificate generation failed: #{inspect(e)}")
      {:error, {:signing_failed, e}}
  end

  defp extract_public_key_from_csr(csr_pem) when is_binary(csr_pem) do
    case X509.CSR.from_pem(csr_pem) do
      {:ok, csr} ->
        if X509.CSR.valid?(csr) do
          X509.CSR.public_key(csr)
        else
          nil
        end

      _ ->
        nil
    end
  rescue
    _ -> nil
  end

  defp extract_public_key_from_csr(_), do: nil

  defp decode_private_key(der, algorithm) do
    case normalize_algo(algorithm) do
      :rsa ->
        {:ok, :public_key.der_decode(:RSAPrivateKey, der)}

      :ec ->
        {:ok, :public_key.der_decode(:ECPrivateKey, der)}

      :unknown ->
        {:error, {:unsupported_algorithm, algorithm}}
    end
  rescue
    e -> {:error, {:key_decode_failed, e}}
  end

  defp normalize_algo(algo) when is_binary(algo) do
    case String.downcase(algo) do
      a when a in ["rsa", "rsa-2048", "rsa-4096"] -> :rsa
      a when a in ["ecc", "ec-p256", "ec-p384", "ecdsa"] -> :ec
      _ -> :unknown
    end
  end

  defp normalize_algo(_), do: :unknown

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

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      nil -> {:error, :issuer_key_not_found}
      key -> {:ok, key}
    end
  end
end
