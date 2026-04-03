defmodule PkiRaPortal.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      PkiRaPortalWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:pki_ra_portal, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: PkiRaPortal.PubSub},
      {Task.Supervisor, name: PkiRaPortal.TaskSupervisor},
      PkiRaPortal.SessionStore,
      # Start to serve requests, typically the last entry
      PkiRaPortalWeb.Endpoint
    ]

    children =
      if Application.get_env(:pki_ra_portal, :start_date_log_handler, true) do
        children ++
          [
            {PkiPlatformEngine.DateLogHandler,
             app_name: "pki_ra_portal", log_dir: "logs", retention_days: 7}
          ]
      else
        children
      end

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: PkiRaPortal.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    PkiRaPortalWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
