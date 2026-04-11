defmodule PkiCaEngine.CeremonyRegistry do
  @moduledoc """
  Process registry for active key ceremonies.

  Maps ceremony IDs to PIDs and monitors registered processes.
  When a ceremony process dies, its entry is automatically removed.
  """
  use GenServer

  def start_link(opts) do
    name = opts[:name] || :ceremony_pid_registry
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  def register(ceremony_id, pid, name \\ :ceremony_pid_registry) do
    GenServer.call(name, {:register, ceremony_id, pid})
  end

  def lookup(ceremony_id, name \\ :ceremony_pid_registry) do
    GenServer.call(name, {:lookup, ceremony_id})
  end

  def unregister(ceremony_id, name \\ :ceremony_pid_registry) do
    GenServer.call(name, {:unregister, ceremony_id})
  end

  # -- Callbacks --

  @impl true
  def init(_opts) do
    {:ok, %{ceremonies: %{}, monitors: %{}}}
  end

  @impl true
  def handle_call({:register, ceremony_id, pid}, _from, state) do
    # Clean up any existing entry for this ceremony_id to prevent monitor leaks
    state =
      case Map.get(state.ceremonies, ceremony_id) do
        nil ->
          state

        _old_pid ->
          old_ref = Enum.find_value(state.monitors, fn {r, cid} -> if cid == ceremony_id, do: r end)
          if old_ref, do: Process.demonitor(old_ref, [:flush])
          %{state | monitors: Map.delete(state.monitors, old_ref)}
      end

    ref = Process.monitor(pid)

    new_state = %{
      state
      | ceremonies: Map.put(state.ceremonies, ceremony_id, pid),
        monitors: Map.put(state.monitors, ref, ceremony_id)
    }

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call({:lookup, ceremony_id}, _from, state) do
    case Map.get(state.ceremonies, ceremony_id) do
      nil -> {:reply, {:error, :not_found}, state}
      pid -> {:reply, {:ok, pid}, state}
    end
  end

  @impl true
  def handle_call({:unregister, ceremony_id}, _from, state) do
    # Find and cancel the monitor for this ceremony
    {ref, remaining_monitors} =
      Enum.reduce(state.monitors, {nil, state.monitors}, fn {r, cid}, {found, acc} ->
        if cid == ceremony_id, do: {r, Map.delete(acc, r)}, else: {found, acc}
      end)

    if ref, do: Process.demonitor(ref, [:flush])

    new_state = %{
      state
      | ceremonies: Map.delete(state.ceremonies, ceremony_id),
        monitors: remaining_monitors
    }

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, _} ->
        {:noreply, state}

      {ceremony_id, remaining_monitors} ->
        {:noreply, %{
          state
          | ceremonies: Map.delete(state.ceremonies, ceremony_id),
            monitors: remaining_monitors
        }}
    end
  end
end
