defmodule PkiCaEngine.CertificateSigning do
  @moduledoc """
  Certificate Signing Pipeline.

  RA sends approved CSR + cert profile -> CA verifies key active ->
  applies profile -> signs -> stores -> returns cert.
  """

  alias PkiCaEngine.{Repo, KeyActivation}
  alias PkiCaEngine.Schema.IssuedCertificate
  import Ecto.Query
  import PkiCaEngine.QueryHelpers

  @doc """
  Signs a certificate using the given issuer key.

  Verifies the key is active via KeyActivation, generates a serial number,
  creates and stores an IssuedCertificate record.

  Options:
    - `:activation_server` - the KeyActivation server to use (default: KeyActivation)
  """
  def sign_certificate(issuer_key_id, csr_data, cert_profile, opts \\ []) do
    activation_server = opts[:activation_server] || KeyActivation

    with {:ok, _secret} <- KeyActivation.get_active_key(activation_server, issuer_key_id) do
      serial = generate_serial()
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      validity_days = Map.get(cert_profile, :validity_days, 365)
      not_after = DateTime.add(now, validity_days * 86400, :second)

      subject_dn = Map.get(cert_profile, :subject_dn, extract_subject_from_csr(csr_data))

      # Placeholder signing - in production this would use the secret key
      cert_der = "CERT_DER_" <> serial
      cert_pem = "CERT_PEM_" <> serial

      %IssuedCertificate{}
      |> IssuedCertificate.changeset(%{
        serial_number: serial,
        issuer_key_id: issuer_key_id,
        subject_dn: subject_dn,
        cert_der: cert_der,
        cert_pem: cert_pem,
        not_before: now,
        not_after: not_after,
        cert_profile_id: cert_profile[:id]
      })
      |> Repo.insert()
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
        cert
        |> Ecto.Changeset.change(
          status: "revoked",
          revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
          revocation_reason: reason
        )
        |> Repo.update()

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
    |> order_by(asc: :id)
    |> Repo.all()
  end

  defp generate_serial do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp extract_subject_from_csr(csr_data) when is_binary(csr_data) do
    # Placeholder - real implementation would parse the CSR ASN.1 structure
    "CN=placeholder,O=test"
  end

end
