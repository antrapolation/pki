defmodule PkiPlatformEngine.TenantProcess do
  @moduledoc """
  Per-tenant supervisor. Starts dynamic Ecto Repos connected to the tenant's
  database with schema-specific search_paths (ca, ra, audit).

  Registers the Repo names in TenantRegistry after children start successfully.
  """
  use Supervisor

  alias PkiPlatformEngine.TenantRegistry

  require Logger

  def start_link(opts) do
    tenant = Keyword.fetch!(opts, :tenant)
    registry = Keyword.get(opts, :registry, TenantRegistry)

    ca_repo_name = :"ca_repo_#{tenant.id}"
    ra_repo_name = :"ra_repo_#{tenant.id}"
    audit_repo_name = :"audit_repo_#{tenant.id}"

    # Start supervisor and children first, then register.
    # If registration fails, stop the supervisor to avoid orphaned processes.
    case Supervisor.start_link(__MODULE__, {tenant, ca_repo_name, ra_repo_name, audit_repo_name}, name: via(tenant.id)) do
      {:ok, pid} ->
        case TenantRegistry.register(registry, tenant.id, %{
               ca_repo: ca_repo_name,
               ra_repo: ra_repo_name,
               audit_repo: audit_repo_name,
               slug: tenant.slug,
               tenant: tenant
             }) do
          :ok ->
            Logger.info("[TenantProcess] Engines ready for tenant #{tenant.slug} (#{tenant.id})")
            {:ok, pid}

          {:error, reason} ->
            Logger.error("[TenantProcess] Registry failed for tenant #{tenant.slug}: #{inspect(reason)}, stopping supervisor")
            Supervisor.stop(pid, :normal)
            {:error, {:registration_failed, reason}}
        end

      {:error, reason} = err ->
        Logger.error("[TenantProcess] Failed to start engines for tenant #{tenant.slug}: #{inspect(reason)}")
        err
    end
  end

  def via(tenant_id), do: {:global, {__MODULE__, tenant_id}}

  @impl true
  def init({tenant, ca_repo_name, ra_repo_name, audit_repo_name}) do
    base_config = base_repo_config(tenant.database_name)

    children = [
      repo_child_spec(ca_repo_name, base_config, "ca"),
      repo_child_spec(ra_repo_name, base_config, "ra"),
      repo_child_spec(audit_repo_name, base_config, "audit")
    ]

    Supervisor.init(children, strategy: :one_for_all)
  end

  defp base_repo_config(database_name) do
    config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.TenantRepo, [])
    platform_config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.PlatformRepo, [])

    # Tenant repos connect directly to PostgreSQL (port 5432), bypassing PgBouncer.
    # PgBouncer's transaction-mode pooling runs DISCARD ALL between transactions,
    # which resets the search_path we set via after_connect. Direct connections
    # keep the search_path for the lifetime of the connection.
    [
      hostname: Keyword.get(config, :hostname, Keyword.get(platform_config, :hostname, "localhost")),
      port: Keyword.get(config, :direct_port, 5432),
      username: Keyword.get(config, :username, Keyword.get(platform_config, :username, "postgres")),
      password: Keyword.get(config, :password, Keyword.get(platform_config, :password, "postgres")),
      database: database_name,
      pool_size: String.to_integer(System.get_env("TENANT_POOL_SIZE", "5"))
    ]
  end

  defp repo_child_spec(name, base_config, schema_prefix) do
    config =
      base_config
      |> Keyword.put(:name, name)
      |> Keyword.put(:after_connect, {Postgrex, :query!, ["SET search_path TO #{schema_prefix}", []]})
      |> Keyword.put(:prepare, :unnamed)

    %{
      id: name,
      start: {PkiPlatformEngine.DynamicRepo, :start_link, [config]},
      type: :supervisor
    }
  end
end
