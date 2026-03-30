defmodule PkiPlatformEngine.TenantSupervisor do
  @moduledoc """
  DynamicSupervisor that manages TenantProcess children — one per active tenant.
  """
  use DynamicSupervisor

  alias PkiPlatformEngine.{TenantProcess, TenantRegistry}

  require Logger

  def start_link(opts \\ []) do
    DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @doc "Start engine processes for a tenant."
  def start_tenant(tenant, registry \\ TenantRegistry) do
    case DynamicSupervisor.start_child(__MODULE__, {TenantProcess, tenant: tenant, registry: registry}) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Stop engine processes for a tenant."
  def stop_tenant(tenant_id, registry \\ TenantRegistry) do
    # Terminate child first, then unregister — prevents fallback to wrong Repo
    case GenServer.whereis(TenantProcess.via(tenant_id)) do
      nil -> :ok
      pid -> DynamicSupervisor.terminate_child(__MODULE__, pid)
    end

    TenantRegistry.unregister(registry, tenant_id)
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
