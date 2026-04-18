defmodule PkiReplica.PortAllocator do
  @moduledoc """
  In-memory port pool allocator for promoted tenant HTTP endpoints.

  Pool range: 5001-5999 (999 ports).
  No PostgreSQL persistence — purely in-memory via GenServer state.

  ## API

    * `allocate/1` — assigns the next available port to a tenant slug
    * `release/1` — frees the port assigned to a tenant slug
    * `get_port/1` — looks up the port for a tenant slug
  """
  use GenServer

  @pool_start 5001
  @pool_end 5999

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Allocate a port for the given tenant slug. Returns `{:ok, port}` or `{:error, reason}`."
  def allocate(slug) do
    GenServer.call(__MODULE__, {:allocate, slug})
  end

  @doc "Release the port allocated to a tenant slug. Returns `:ok`."
  def release(slug) do
    GenServer.call(__MODULE__, {:release, slug})
  end

  @doc "Get the port allocated to a tenant slug. Returns `{:ok, port}` or `{:error, :not_found}`."
  def get_port(slug) do
    GenServer.call(__MODULE__, {:get_port, slug})
  end

  # -- GenServer callbacks --

  @impl true
  def init(_opts) do
    state = %{
      # slug -> port
      allocations: %{},
      # port -> slug (reverse index for fast release)
      ports_in_use: MapSet.new(),
      next_port: @pool_start
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:allocate, slug}, _from, state) do
    case Map.get(state.allocations, slug) do
      nil ->
        case find_available_port(state) do
          {:ok, port} ->
            allocations = Map.put(state.allocations, slug, port)
            ports_in_use = MapSet.put(state.ports_in_use, port)
            next_port = port + 1
            state = %{state | allocations: allocations, ports_in_use: ports_in_use, next_port: next_port}
            {:reply, {:ok, port}, state}

          :exhausted ->
            {:reply, {:error, :pool_exhausted}, state}
        end

      existing_port ->
        # Already allocated — return existing
        {:reply, {:ok, existing_port}, state}
    end
  end

  def handle_call({:release, slug}, _from, state) do
    case Map.pop(state.allocations, slug) do
      {nil, _} ->
        {:reply, :ok, state}

      {port, allocations} ->
        ports_in_use = MapSet.delete(state.ports_in_use, port)
        {:reply, :ok, %{state | allocations: allocations, ports_in_use: ports_in_use}}
    end
  end

  def handle_call({:get_port, slug}, _from, state) do
    case Map.get(state.allocations, slug) do
      nil -> {:reply, {:error, :not_found}, state}
      port -> {:reply, {:ok, port}, state}
    end
  end

  # -- Internal --

  defp find_available_port(state) do
    find_port_from(state.next_port, state.ports_in_use)
  end

  defp find_port_from(port, _ports_in_use) when port > @pool_end do
    # Wrap around and scan from start
    find_port_scan(@pool_start, @pool_end, _ports_in_use)
  end

  defp find_port_from(port, ports_in_use) do
    if MapSet.member?(ports_in_use, port) do
      find_port_from(port + 1, ports_in_use)
    else
      {:ok, port}
    end
  end

  defp find_port_scan(port, max, _ports_in_use) when port > max, do: :exhausted

  defp find_port_scan(port, max, ports_in_use) do
    if MapSet.member?(ports_in_use, port) do
      find_port_scan(port + 1, max, ports_in_use)
    else
      {:ok, port}
    end
  end
end
