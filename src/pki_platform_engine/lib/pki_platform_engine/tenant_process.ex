defmodule PkiPlatformEngine.TenantProcess do
  @moduledoc """
  Per-tenant supervisor. Starts dynamic Ecto Repos connected to the tenant's
  database with schema-specific search_paths (ca, ra, audit).

  Registers the Repo names in TenantRegistry on init.
  """
  use Supervisor

  alias PkiPlatformEngine.TenantRegistry

  require Logger

  def start_link(opts) do
    tenant = Keyword.fetch!(opts, :tenant)
    registry = Keyword.get(opts, :registry, TenantRegistry)
    Supervisor.start_link(__MODULE__, {tenant, registry}, name: via(tenant.id))
  end

  def via(tenant_id), do: {:global, {__MODULE__, tenant_id}}

  @impl true
  def init({tenant, registry}) do
    base_config = base_repo_config(tenant.database_name)

    ca_repo_name = :"ca_repo_#{tenant.id}"
    ra_repo_name = :"ra_repo_#{tenant.id}"
    audit_repo_name = :"audit_repo_#{tenant.id}"

    # Register before starting children so lookups work as soon as repos are up
    TenantRegistry.register(registry, tenant.id, %{
      ca_repo: ca_repo_name,
      ra_repo: ra_repo_name,
      audit_repo: audit_repo_name,
      slug: tenant.slug,
      tenant: tenant
    })

    children = [
      repo_child_spec(ca_repo_name, base_config, "ca"),
      repo_child_spec(ra_repo_name, base_config, "ra"),
      repo_child_spec(audit_repo_name, base_config, "ca")
    ]

    Logger.info("[TenantProcess] Starting engines for tenant #{tenant.slug} (#{tenant.id})")

    Supervisor.init(children, strategy: :one_for_all)
  end

  defp base_repo_config(database_name) do
    # Read connection config from the TenantRepo config (same DB server, different database)
    config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.TenantRepo, [])

    # Fall back to PlatformRepo config if TenantRepo config is not set
    platform_config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.PlatformRepo, [])

    [
      hostname: Keyword.get(config, :hostname, Keyword.get(platform_config, :hostname, "localhost")),
      port: Keyword.get(config, :port, Keyword.get(platform_config, :port, 5434)),
      username: Keyword.get(config, :username, Keyword.get(platform_config, :username, "postgres")),
      password: Keyword.get(config, :password, Keyword.get(platform_config, :password, "postgres")),
      database: database_name,
      pool_size: 5
    ]
  end

  defp repo_child_spec(name, base_config, schema_prefix) do
    config =
      base_config
      |> Keyword.put(:name, name)
      |> Keyword.put(:after_connect, {Postgrex, :query!, ["SET search_path TO #{schema_prefix}", []]})

    %{
      id: name,
      start: {PkiPlatformEngine.DynamicRepo, :start_link, [config]},
      type: :supervisor
    }
  end
end
