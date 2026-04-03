defmodule PkiRaEngine.CsrValidation.DefaultCaClient do
  @moduledoc """
  Default CA client — stub that returns an error.

  In production, configure `:ca_engine_module` to point to the real
  CA engine RPC client. This placeholder prevents crashes when the
  CA engine integration is not yet wired up.
  """

  @behaviour PkiRaEngine.CaClient

  @impl true
  def sign_certificate(_tenant_id, _issuer_key_id, _csr_pem, _cert_profile) do
    {:error, :ca_engine_not_configured}
  end

  @impl true
  def revoke_certificate(_tenant_id, _serial_number, _reason) do
    {:error, :ca_engine_not_configured}
  end
end
