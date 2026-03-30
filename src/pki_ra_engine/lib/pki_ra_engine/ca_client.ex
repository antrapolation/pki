defmodule PkiRaEngine.CaClient do
  @moduledoc "Behaviour for CA Engine client implementations."

  @callback sign_certificate(tenant_id :: String.t(), issuer_key_id :: String.t(), csr_pem :: String.t(), cert_profile :: map()) ::
              {:ok, map()} | {:error, term()}
end
