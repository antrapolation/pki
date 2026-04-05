defmodule PkiRaEngine.CsrValidation.DirectCaClient do
  @moduledoc """
  Direct (in-process) CA client for single-node deployments.

  Calls PkiCaEngine.CertificateSigning directly without HTTP.
  Use when RA and CA engines run in the same BEAM node.

  Config:
      config :pki_ra_engine, :ca_engine_module, PkiRaEngine.CsrValidation.DirectCaClient
  """

  @behaviour PkiRaEngine.CaClient

  require Logger

  @impl true
  def sign_certificate(tenant_id, issuer_key_id, csr_pem, cert_profile) do
    validity_days = Map.get(cert_profile, :validity_days) || Map.get(cert_profile, "validity_days") || 365

    cert_profile_map = %{
      validity_days: validity_days,
      subject_dn: Map.get(cert_profile, :subject_dn) || Map.get(cert_profile, "subject_dn")
    }

    case PkiCaEngine.CertificateSigning.sign_certificate(tenant_id, issuer_key_id, csr_pem, cert_profile_map) do
      {:ok, cert} ->
        {:ok, %{
          serial_number: cert.serial_number,
          cert_pem: cert.cert_pem,
          subject_dn: cert.subject_dn
        }}

      {:error, reason} ->
        Logger.error("direct_ca_sign_failed issuer_key=#{issuer_key_id} reason=#{inspect(reason)}")
        {:error, reason}
    end
  end

  @impl true
  def revoke_certificate(_tenant_id, _serial_number, _reason) do
    # CA engine revocation module not yet implemented
    {:error, :revocation_not_implemented}
  end
end
