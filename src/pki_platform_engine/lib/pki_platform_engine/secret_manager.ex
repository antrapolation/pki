defmodule PkiPlatformEngine.SecretManager do
  @moduledoc """
  Behaviour + dispatch for the platform master-key source.

  Used as the KEK input to `PkiPlatformEngine.SofthsmPinCustody` and
  reserved for any other "needs the platform-wide master key"
  caller. The actual backend is pluggable via config:

      config :pki_platform_engine, :secret_manager,
        PkiPlatformEngine.SecretManager.EnvBackend

  The env-var backend is the only one shipped today. Future
  additions (AWS SSM, HashiCorp Vault, GCP Secret Manager) slot in
  by implementing the same behaviour.

  The returned key is **always 32 raw bytes** — call sites derive
  per-use sub-keys via HKDF rather than using the master key
  directly.
  """

  @callback master_key() :: {:ok, <<_::256>>} | {:error, term()}

  @default_backend PkiPlatformEngine.SecretManager.EnvBackend

  @doc """
  Fetch the platform master key as 32 raw bytes.

  Returns `{:error, :no_master_key}` if the configured backend has
  nothing to return (the typical dev / CI shape — PIN custody
  falls back to `.pins` on disk in that case).
  """
  @spec master_key() :: {:ok, <<_::256>>} | {:error, term()}
  def master_key do
    backend().master_key()
  end

  defp backend do
    Application.get_env(:pki_platform_engine, :secret_manager, @default_backend)
  end
end
