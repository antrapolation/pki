defmodule PkiTenant.Application do
  @moduledoc """
  Tenant application supervisor.

  Boot order (primary mode):
  1. MnesiaBootstrap — opens/creates Mnesia tables
  2. MnesiaBackup — periodic backup timer
  3. AuditBridge — connects to platform node for audit forwarding
  4. CA Engine Supervisor — key activation, ceremony orchestrator
  5. RA Engine Supervisor — CSR processing, cert profiles
  6. Validation Supervisor — CRL publisher
  7. Task.Supervisor — ad-hoc async tasks

  In replica mode (REPLICA_MODE=true), only MnesiaBootstrap and AuditBridge
  are started — no CA/RA/Validation engines or web endpoint.
  """
  use Application

  @impl true
  def start(_type, _args) do
    tenant_id = System.get_env("TENANT_ID") || "dev"
    tenant_slug = System.get_env("TENANT_SLUG") || "dev"
    platform_node = System.get_env("PLATFORM_NODE")
    replica_mode = System.get_env("REPLICA_MODE") == "true"

    children =
      cond do
        # Test mode — empty tree
        not Application.get_env(:pki_tenant, :start_application, true) ->
          []

        # Replica mode — only Mnesia replication + audit bridge
        replica_mode ->
          [
            {PkiTenant.MnesiaBootstrap, [slug: tenant_slug]},
            {PkiTenant.AuditBridge, [tenant_id: tenant_id, platform_node: platform_node]}
          ]

        # Primary mode — full supervision tree (existing behavior)
        true ->
          [
            {PkiTenant.MnesiaBootstrap, [slug: tenant_slug]},
            {PkiTenant.MnesiaBackup, [start_timer: true]},
            {PkiTenant.AuditBridge, [tenant_id: tenant_id, platform_node: platform_node]},
            {PkiCaEngine.EngineSupervisor, []},
            {PkiRaEngine.EngineSupervisor, []},
            {PkiValidation.Supervisor, []},
            {Task.Supervisor, name: PkiTenant.TaskSupervisor}
          ]
      end

    opts = [strategy: :one_for_one, name: PkiTenant.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
