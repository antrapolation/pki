defmodule PkiPlatformEngine.TenantHealthMonitor do
  @moduledoc """
  Periodic health check for all running tenants via :erpc.call.
  """
  use GenServer
  require Logger

  @check_interval_ms 30_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def get_health do
    GenServer.call(__MODULE__, :get_health)
  end

  @impl true
  def init(_opts) do
    schedule_check()
    {:ok, %{health: %{}}}
  end

  @impl true
  def handle_call(:get_health, _from, state) do
    {:reply, state.health, state}
  end

  @impl true
  def handle_info(:check, state) do
    tenants = PkiPlatformEngine.TenantLifecycle.list_tenants()

    health_results =
      Enum.map(tenants, fn tenant ->
        result = check_tenant(tenant.node)
        {tenant.id, result}
      end)
      |> Map.new()

    schedule_check()
    {:noreply, %{state | health: health_results}}
  end

  defp check_tenant(node) do
    case :erpc.call(node, PkiTenant.Health, :check, [], 5_000) do
      %{status: :ok} = health -> {:healthy, health}
      other -> {:unhealthy, other}
    end
  rescue
    _ -> {:unreachable, nil}
  catch
    :exit, _ -> {:unreachable, nil}
  end

  defp schedule_check do
    Process.send_after(self(), :check, @check_interval_ms)
  end
end
