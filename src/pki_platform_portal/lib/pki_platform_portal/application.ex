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
    Supervisor.start_link(children, opts)
  end

  @impl true
  def config_change(changed, _new, removed) do
    PkiPlatformPortalWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
