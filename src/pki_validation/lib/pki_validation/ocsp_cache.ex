defmodule PkiValidation.OcspCache do
  @moduledoc """
  ETS-backed cache for OCSP responses with configurable TTL.

  Provides fast lookups for certificate status, reducing database load.
  """

  use GenServer

  @table_name :ocsp_cache
  @default_ttl_ms :timer.minutes(5)
  @cleanup_interval_ms :timer.minutes(1)

  # Client API

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Get a cached value by serial number.
  Returns `{:ok, value}` if found and not expired, `:miss` otherwise.
  """
  def get(serial_number, table \\ @table_name) do
    now = System.monotonic_time(:millisecond)

    # Atomically delete expired entries for this key, avoiding TOCTOU races
    :ets.select_delete(table, [
      {{serial_number, :_, :"$1"}, [{:<, :"$1", now}], [true]}
    ])

    case :ets.lookup(table, serial_number) do
      [{^serial_number, value, _expires_at}] ->
        {:ok, value}

      [] ->
        :miss
    end
  end

  @doc """
  Cache a value with optional TTL (defaults to 5 minutes).
  """
  def put(serial_number, value, opts \\ []) do
    table = Keyword.get(opts, :table, @table_name)
    ttl = Keyword.get(opts, :ttl, @default_ttl_ms)
    expires_at = System.monotonic_time(:millisecond) + ttl
    :ets.insert(table, {serial_number, value, expires_at})
    :ok
  end

  @doc """
  Remove a cached entry.
  """
  def invalidate(serial_number, table \\ @table_name) do
    :ets.delete(table, serial_number)
    :ok
  end

  # Server callbacks

  @impl true
  def init(opts) do
    table_name = Keyword.get(opts, :table_name, @table_name)
    table = :ets.new(table_name, [:set, :public, :named_table, read_concurrency: true])
    schedule_cleanup()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now = System.monotonic_time(:millisecond)

    :ets.select_delete(state.table, [
      {{:_, :_, :"$1"}, [{:<, :"$1", now}], [true]}
    ])

    schedule_cleanup()
    {:noreply, state}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end
end
