defmodule PkiPlatformPortal.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    hash_admin_password()

    children = [
      PkiPlatformPortalWeb.Telemetry,
      {DNSCluster,
       query: Application.get_env(:pki_platform_portal, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: PkiPlatformPortal.PubSub},
      PkiPlatformPortalWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: PkiPlatformPortal.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Hash the plaintext admin password at startup so it never sits in app config
  # as cleartext beyond the first request. If PLATFORM_ADMIN_PASSWORD_HASH was
  # set directly (pre-hashed), we skip hashing.
  defp hash_admin_password do
    case Application.get_env(:pki_platform_portal, :admin_password_hash) do
      hash when is_binary(hash) ->
        :ok

      _ ->
        plain = Application.get_env(:pki_platform_portal, :admin_password, "admin")
        hash = Argon2.hash_pwd_salt(plain)
        Application.put_env(:pki_platform_portal, :admin_password_hash, hash)
        Application.delete_env(:pki_platform_portal, :admin_password)
    end
  end

  @impl true
  def config_change(changed, _new, removed) do
    PkiPlatformPortalWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
