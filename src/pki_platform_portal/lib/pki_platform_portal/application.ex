defmodule PkiPlatformPortal.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      PkiPlatformPortalWeb.Telemetry,
      {DNSCluster,
       query: Application.get_env(:pki_platform_portal, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: PkiPlatformPortal.PubSub},
      PkiPlatformPortalWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: PkiPlatformPortal.Supervisor]
    result = Supervisor.start_link(children, opts)

    # Seed first admin from env vars if DB has no admins (backward compatibility)
    try do
      PkiPlatformEngine.AdminManagement.seed_from_env()
    rescue
      e -> require Logger; Logger.warning("Failed to seed admin from env: #{inspect(e)}")
    end

    result
  end

  @impl true
  def config_change(changed, _new, removed) do
    PkiPlatformPortalWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
