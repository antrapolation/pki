defmodule PkiRaEngine.CaClient do
  @moduledoc "Behaviour for CA Engine client implementations."

  @callback sign_certificate(csr_pem :: String.t(), cert_profile :: map()) ::
              {:ok, map()} | {:error, term()}
end
