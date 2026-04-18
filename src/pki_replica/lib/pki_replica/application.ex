defmodule PkiReplica.Application do
  @moduledoc """
  Supervision tree for the pki_replica app.

  Children:
  1. ClusterMonitor — heartbeat monitoring of the primary platform node
  2. FailoverManager — alert + manual promotion orchestration
  3. PortAllocator — in-memory port pool for post-promotion HTTP endpoints
  """
  use Application

  @impl true
  def start(_type, _args) do
    if Application.get_env(:pki_replica, :start_application, true) do
      start_supervised_tree()
    else
      Supervisor.start_link([], strategy: :one_for_one, name: PkiReplica.Supervisor)
    end
  end

  defp start_supervised_tree do
    primary_node =
      Application.get_env(:pki_replica, :primary_platform_node, :"pki_platform@server1")

    heartbeat_interval =
      Application.get_env(:pki_replica, :heartbeat_interval_ms, 5_000)

    failure_threshold =
      Application.get_env(:pki_replica, :heartbeat_failure_threshold, 3)

    webhook_url = Application.get_env(:pki_replica, :webhook_url)
    alert_log_path = Application.get_env(:pki_replica, :alert_log_path, "/var/log/pki/failover-alert.log")

    children = [
      {PkiReplica.ClusterMonitor,
       primary_node: primary_node,
       interval_ms: heartbeat_interval,
       failure_threshold: failure_threshold},
      {PkiReplica.FailoverManager,
       webhook_url: webhook_url,
       alert_log_path: alert_log_path},
      {PkiReplica.PortAllocator, []}
    ]

    opts = [strategy: :one_for_one, name: PkiReplica.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
