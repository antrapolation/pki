defmodule PkiPlatformEngine.TenantSupervisor do
  @moduledoc """
  DynamicSupervisor that manages TenantProcess children — one per active tenant.

  Schema-mode tenants skip TenantProcess entirely (no per-tenant processes needed)
  and are registered directly in TenantRegistry with prefix info.
  Database-mode (legacy) tenants follow the existing path: start a TenantProcess
  with 3 DynamicRepo children per tenant.
  """
  use DynamicSupervisor

  alias PkiPlatformEngine.{TenantLifecycle, TenantPrefix, TenantProcess, TenantRegistry}

  require Logger

  def start_link(opts \\ []) do
    DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @doc "Start engine processes for a tenant."
  def start_tenant(tenant, registry \\ TenantRegistry)

  def start_tenant(%{schema_mode: "schema"} = tenant, registry) do
    # Schema-mode: no per-tenant processes needed.
    # Register prefix info directly in TenantRegistry.
    prefixes = TenantPrefix.all_prefixes(tenant.id)

    TenantRegistry.register(registry, tenant.id, %{
      schema_mode: "schema",
      ca_prefix: prefixes.ca_prefix,
      ra_prefix: prefixes.ra_prefix,
      audit_prefix: prefixes.audit_prefix,
      slug: tenant.slug,
      tenant: tenant
    })

    Logger.info("[TenantSupervisor] Schema-mode tenant #{tenant.name} (#{tenant.slug}) registered")
    {:ok, :schema_mode}
  end

  def start_tenant(%{schema_mode: "beam"} = tenant, _registry) do
    # BEAM-mode: spawn a per-tenant peer node via TenantLifecycle.
    # Called on platform boot — PortAllocator rehydrates prior port
    # assignments from PG so each tenant gets back its previous port.
    # Already-running peers are a no-op: create_tenant short-circuits
    # when the tenant id is already in lifecycle state.
    case TenantLifecycle.get_tenant(tenant.id) do
      {:ok, info} ->
        Logger.info(
          "[TenantSupervisor] BEAM tenant #{tenant.name} (#{tenant.slug}) already running on #{info.node}"
        )

        {:ok, info}

      {:error, :not_found} ->
        # Rehydrate the tenant's SOFTHSM2_CONF from metadata so the
        # respawned peer points at its own token dir instead of the
        # system default. Nil is safe (peer boots without per-tenant
        # HSM isolation). Also tolerates bare test-fixture maps that
        # don't carry a :metadata field at all.
        softhsm_conf =
          case Map.get(tenant, :metadata) do
            %{"softhsm" => %{"conf_path" => path}} when is_binary(path) -> path
            _ -> nil
          end

        create_attrs = %{id: tenant.id, slug: tenant.slug, softhsm_conf: softhsm_conf}

        with {:ok, info} <- TenantLifecycle.create_tenant(create_attrs),
             :ok <- TenantLifecycle.boot_tenant_apps(info.node, info.port) do
          Logger.info(
            "[TenantSupervisor] Respawned BEAM tenant #{tenant.name} (#{tenant.slug}) on port #{info.port}"
          )

          {:ok, info}
        end
    end
  end

  def start_tenant(tenant, registry) do
    # Database-mode (legacy): start per-tenant DynamicRepo processes
    case DynamicSupervisor.start_child(__MODULE__, {TenantProcess, tenant: tenant, registry: registry}) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Stop engine processes for a tenant."
  def stop_tenant(tenant_id, registry \\ TenantRegistry) do
    # BEAM tenants are tracked in TenantLifecycle, not TenantRegistry —
    # check there first and shut the peer down gracefully if present.
    case TenantLifecycle.get_tenant(tenant_id) do
      {:ok, _info} ->
        _ = TenantLifecycle.stop_tenant(tenant_id)
        :ok

      {:error, :not_found} ->
        stop_non_beam_tenant(tenant_id, registry)
    end
  end

  defp stop_non_beam_tenant(tenant_id, registry) do
    # Check if this is a schema-mode tenant (no process to terminate)
    case TenantRegistry.lookup(registry, tenant_id) do
      {:ok, %{schema_mode: "schema"}} ->
        TenantRegistry.unregister(registry, tenant_id)

      _ ->
        # Database-mode: terminate child process first, then unregister
        case GenServer.whereis(TenantProcess.via(tenant_id)) do
          nil -> :ok
          pid -> DynamicSupervisor.terminate_child(__MODULE__, pid)
        end

        TenantRegistry.unregister(registry, tenant_id)
    end
  end

  @doc "Start engine processes for all active tenants. Called on application boot."
  def boot_active_tenants(registry \\ TenantRegistry) do
    PkiPlatformEngine.Provisioner.list_tenants()
    |> Enum.filter(&(&1.status == "active"))
    |> Enum.each(fn tenant ->
      case start_tenant(tenant, registry) do
        {:ok, _} ->
          Logger.info("[TenantSupervisor] Started engines for tenant #{tenant.name} (#{tenant.slug})")

        {:error, reason} ->
          Logger.error("[TenantSupervisor] Failed to start tenant #{tenant.name}: #{inspect(reason)}")
      end
    end)
  end
end
