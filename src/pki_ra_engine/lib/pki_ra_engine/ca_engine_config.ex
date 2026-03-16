defmodule PkiRaEngine.CaEngineConfig do
  @moduledoc """
  CA Engine Configuration — simple GenServer-based key-value store
  for CA engine connection parameters (node reference, port, etc.).
  """

  use GenServer

  # ── Client API ──────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  @doc "Set a configuration key."
  @spec set(atom(), term()) :: :ok
  def set(key, value) do
    GenServer.call(__MODULE__, {:set, key, value})
  end

  @doc "Get a configuration value by key."
  @spec get(atom()) :: {:ok, term()} | {:error, :not_found}
  def get(key) do
    GenServer.call(__MODULE__, {:get, key})
  end

  @doc "Get all configuration as a map."
  @spec get_all() :: map()
  def get_all do
    GenServer.call(__MODULE__, :get_all)
  end

  @doc "Delete a configuration key."
  @spec delete(atom()) :: :ok
  def delete(key) do
    GenServer.call(__MODULE__, {:delete, key})
  end

  @doc "Clear all configuration."
  @spec clear() :: :ok
  def clear do
    GenServer.call(__MODULE__, :clear)
  end

  # ── Server Callbacks ────────────────────────────────────────────────

  @impl true
  def init(state) do
    {:ok, state}
  end

  @impl true
  def handle_call({:set, key, value}, _from, state) do
    {:reply, :ok, Map.put(state, key, value)}
  end

  @impl true
  def handle_call({:get, key}, _from, state) do
    case Map.fetch(state, key) do
      {:ok, value} -> {:reply, {:ok, value}, state}
      :error -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_all, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_call({:delete, key}, _from, state) do
    {:reply, :ok, Map.delete(state, key)}
  end

  @impl true
  def handle_call(:clear, _from, _state) do
    {:reply, :ok, %{}}
  end
end
