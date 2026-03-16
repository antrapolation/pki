defmodule PkiRaEngine.CsrValidation.DefaultCaClient do
  @moduledoc """
  Default CA client — stub that returns an error.

  In production, configure `:ca_engine_module` to point to the real
  CA engine RPC client. This placeholder prevents crashes when the
  CA engine integration is not yet wired up.
  """

  def sign_certificate(_csr_pem, _cert_profile) do
    {:error, :ca_engine_not_configured}
  end
end
