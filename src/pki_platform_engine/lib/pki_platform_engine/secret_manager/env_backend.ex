defmodule PkiPlatformEngine.SecretManager.EnvBackend do
  @moduledoc """
  Reads the platform master key from the `PKI_PLATFORM_MASTER_KEY`
  environment variable.

  The variable must hold **32 random bytes base64-encoded** (use
  e.g. `openssl rand -base64 32`). Any other length — or the
  variable missing entirely — surfaces as `{:error, _}`, at which
  point callers fall back to their non-encrypted code path (see
  `PkiPlatformEngine.SofthsmPinCustody`).

  The variable name can be overridden for tests via
  `:pki_platform_engine, :master_key_env` config, but production
  deployments should leave it at the default.
  """

  @behaviour PkiPlatformEngine.SecretManager

  @default_env_var "PKI_PLATFORM_MASTER_KEY"

  @impl true
  def master_key do
    env_var = Application.get_env(:pki_platform_engine, :master_key_env, @default_env_var)

    case System.get_env(env_var) do
      nil -> {:error, :no_master_key}
      "" -> {:error, :no_master_key}
      encoded -> decode(encoded)
    end
  end

  defp decode(encoded) do
    case Base.decode64(encoded, padding: false) do
      {:ok, <<_::256>> = key} -> {:ok, key}
      {:ok, _wrong_length} -> {:error, :invalid_key_length}
      :error -> {:error, :invalid_base64}
    end
  rescue
    # Defensive — Base.decode64 doesn't usually raise, but a
    # malformed env var shouldn't crash the caller.
    _ -> {:error, :invalid_master_key}
  end
end
