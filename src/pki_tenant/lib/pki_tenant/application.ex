defmodule PkiTenant.Application do
  @moduledoc """
  Tenant application supervisor.

  Boot order:
  1. MnesiaBootstrap — opens/creates Mnesia tables
  2. AuditBridge — connects to platform node for audit forwarding
  3. CA Engine Supervisor — key activation, ceremony orchestrator
  4. RA Engine Supervisor — CSR processing, cert profiles
  5. Validation Supervisor — CRL publisher
  6. Task.Supervisor — ad-hoc async tasks
  """
  use Application

  @impl true
  def start(_type, _args) do
    tenant_id = System.get_env("TENANT_ID") || "dev"
    tenant_slug = System.get_env("TENANT_SLUG") || "dev"
    platform_node = System.get_env("PLATFORM_NODE")

    children =
      if Application.get_env(:pki_tenant, :start_application, true) do
        [
          {PkiTenant.MnesiaBootstrap, [slug: tenant_slug]},
          {PkiTenant.AuditBridge, [tenant_id: tenant_id, platform_node: platform_node]},
          {PkiCaEngine.EngineSupervisor, []},
          {PkiRaEngine.EngineSupervisor, []},
          {PkiValidation.Supervisor, []},
          {Task.Supervisor, name: PkiTenant.TaskSupervisor}
        ]
      else
        # Minimal supervision tree for test environment
        []
      end

    opts = [strategy: :one_for_one, name: PkiTenant.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
