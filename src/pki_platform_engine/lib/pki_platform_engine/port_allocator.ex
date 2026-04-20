defmodule PkiPlatformEngine.PortAllocator do
  @moduledoc """
  Port pool allocator for tenant nodes. Pool: 5001-5999.
  Persists assignments to PostgreSQL for crash recovery.
  """
  use GenServer
  require Logger

  alias PkiPlatformEngine.PlatformRepo

  @default_port_range 5001..5999

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def allocate(tenant_id) do
    GenServer.call(__MODULE__, {:allocate, tenant_id})
  end

  def release(tenant_id) do
    GenServer.call(__MODULE__, {:release, tenant_id})
  end

  def get_port(tenant_id) do
    GenServer.call(__MODULE__, {:get_port, tenant_id})
  end

  def list_assignments do
    GenServer.call(__MODULE__, :list)
  end

  @impl true
  def init(opts) do
    port_range = Keyword.get(opts, :port_range, @default_port_range)
    persist? = Keyword.get(opts, :persist, true)
    assignments = if persist?, do: load_from_pg(), else: %{}
    used_ports = assignments |> Map.values() |> MapSet.new()

    {:ok, %{
      assignments: assignments,
      used_ports: used_ports,
      port_range: port_range,
      persist: persist?
    }}
  end

  @impl true
  def handle_call({:allocate, tenant_id}, _from, state) do
    case Map.get(state.assignments, tenant_id) do
      nil ->
        case find_free_port(state.used_ports, state.port_range) do
          nil ->
            {:reply, {:error, :no_ports_available}, state}

          port ->
            new_assignments = Map.put(state.assignments, tenant_id, port)
            new_used = MapSet.put(state.used_ports, port)
            if state.persist, do: persist_to_pg(tenant_id, port)

            {:reply, {:ok, port}, %{state |
              assignments: new_assignments,
              used_ports: new_used
            }}
        end

      existing_port ->
        {:reply, {:ok, existing_port}, state}
    end
  end

  @impl true
  def handle_call({:release, tenant_id}, _from, state) do
    case Map.pop(state.assignments, tenant_id) do
      {nil, _} ->
        {:reply, :ok, state}

      {port, new_assignments} ->
        new_used = MapSet.delete(state.used_ports, port)
        if state.persist, do: remove_from_pg(tenant_id)

        {:reply, :ok, %{state |
          assignments: new_assignments,
          used_ports: new_used
        }}
    end
  end

  @impl true
  def handle_call({:get_port, tenant_id}, _from, state) do
    {:reply, Map.get(state.assignments, tenant_id), state}
  end

  @impl true
  def handle_call(:list, _from, state) do
    {:reply, state.assignments, state}
  end

  defp find_free_port(used_ports, port_range) do
    Enum.find(port_range, fn port -> not MapSet.member?(used_ports, port) end)
  end

  # PostgreSQL persistence via PlatformRepo
  defp load_from_pg do
    try do
      case PlatformRepo.query("SELECT tenant_id, port FROM tenant_port_assignments", []) do
        {:ok, %{rows: rows}} ->
          rows
          |> Enum.map(fn [tenant_id_bin, port] ->
            {:ok, tid} = Ecto.UUID.cast(tenant_id_bin)
            {tid, port}
          end)
          |> Map.new()

        _ ->
          %{}
      end
    rescue
      _ -> %{}
    end
  end

  defp persist_to_pg(tenant_id, port) do
    try do
      PlatformRepo.query(
        """
        INSERT INTO tenant_port_assignments (tenant_id, port, assigned_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET port = $2, assigned_at = NOW()
        """,
        [Ecto.UUID.dump!(tenant_id), port]
      )
    rescue
      e ->
        Logger.warning("[port_allocator] Failed to persist port assignment for tenant #{tenant_id}: #{Exception.message(e)}")
        :ok
    end
  end

  defp remove_from_pg(tenant_id) do
    try do
      PlatformRepo.query(
        "DELETE FROM tenant_port_assignments WHERE tenant_id = $1",
        [Ecto.UUID.dump!(tenant_id)]
      )
    rescue
      e ->
        Logger.warning("[port_allocator] Failed to remove port assignment for tenant #{tenant_id}: #{Exception.message(e)}")
        :ok
    end
  end
end
