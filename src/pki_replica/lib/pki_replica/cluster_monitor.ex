defmodule PkiReplica.ClusterMonitor do
  @moduledoc """
  Monitors the primary platform node via periodic heartbeat.

  Every `interval_ms` (default 5000), calls `:erpc.call(primary_node, :erlang, :node, [], 3000)`.
  After `failure_threshold` consecutive failures (default 3), declares the primary unreachable
  and notifies the FailoverManager.

  Accepts a `:heartbeat_fn` option for testing — a 1-arity function receiving the primary node,
  which should return `{:ok, node}` or `{:error, reason}`.
  """
  use GenServer

  require Logger

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Returns current monitor status: :connected or :unreachable"
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc "Returns the primary node being monitored"
  def get_primary_node do
    GenServer.call(__MODULE__, :get_primary_node)
  end

  # -- GenServer callbacks --

  @impl true
  def init(opts) do
    primary_node = Keyword.fetch!(opts, :primary_node)
    interval_ms = Keyword.get(opts, :interval_ms, 5_000)
    failure_threshold = Keyword.get(opts, :failure_threshold, 3)

    heartbeat_fn =
      Keyword.get(opts, :heartbeat_fn, &default_heartbeat/1)

    state = %{
      primary_node: primary_node,
      consecutive_failures: 0,
      status: :connected,
      interval_ms: interval_ms,
      failure_threshold: failure_threshold,
      heartbeat_fn: heartbeat_fn
    }

    schedule_heartbeat(interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, state.status, state}
  end

  def handle_call(:get_primary_node, _from, state) do
    {:reply, state.primary_node, state}
  end

  @impl true
  def handle_info(:heartbeat, state) do
    state = perform_heartbeat(state)
    schedule_heartbeat(state.interval_ms)
    {:noreply, state}
  end

  # -- Internal --

  defp perform_heartbeat(state) do
    case state.heartbeat_fn.(state.primary_node) do
      {:ok, _node} ->
        if state.status == :unreachable do
          Logger.info("[ClusterMonitor] Primary #{state.primary_node} reconnected")
        end

        %{state | consecutive_failures: 0, status: :connected}

      {:error, reason} ->
        failures = state.consecutive_failures + 1

        Logger.warning(
          "[ClusterMonitor] Heartbeat to #{state.primary_node} failed " <>
            "(#{failures}/#{state.failure_threshold}): #{inspect(reason)}"
        )

        if failures >= state.failure_threshold and state.status != :unreachable do
          Logger.error(
            "[ClusterMonitor] Primary #{state.primary_node} declared unreachable " <>
              "after #{failures} consecutive failures"
          )

          notify_failover_manager()
          %{state | consecutive_failures: failures, status: :unreachable}
        else
          %{state | consecutive_failures: failures}
        end
    end
  end

  defp default_heartbeat(primary_node) do
    try do
      result = :erpc.call(primary_node, :erlang, :node, [], 3_000)
      {:ok, result}
    catch
      kind, reason ->
        {:error, {kind, reason}}
    end
  end

  defp notify_failover_manager do
    GenServer.cast(PkiReplica.FailoverManager, {:primary_unreachable})
  end

  defp schedule_heartbeat(interval_ms) do
    Process.send_after(self(), :heartbeat, interval_ms)
  end
end
