defmodule PkiReplica.ClusterMonitorTest do
  use ExUnit.Case, async: true

  alias PkiReplica.ClusterMonitor

  @primary_node :"pki_platform@test"

  defp start_monitor(heartbeat_fn, opts \\ []) do
    name = Keyword.get(opts, :name, :"monitor_#{:erlang.unique_integer([:positive])}")

    {:ok, pid} =
      GenServer.start_link(ClusterMonitor, [
        primary_node: @primary_node,
        interval_ms: :timer.hours(1),
        failure_threshold: Keyword.get(opts, :failure_threshold, 3),
        heartbeat_fn: heartbeat_fn
      ], name: name)

    pid
  end

  describe "initial state" do
    test "starts with :connected status" do
      pid = start_monitor(fn _node -> {:ok, @primary_node} end)
      assert GenServer.call(pid, :status) == :connected
    end

    test "reports the primary node" do
      pid = start_monitor(fn _node -> {:ok, @primary_node} end)
      assert GenServer.call(pid, :get_primary_node) == @primary_node
    end
  end

  describe "heartbeat success" do
    test "stays :connected on successful heartbeat" do
      pid = start_monitor(fn _node -> {:ok, @primary_node} end)
      send(pid, :heartbeat)
      # Give it a moment to process
      :sys.get_state(pid)
      assert GenServer.call(pid, :status) == :connected
    end

    test "resets failure count on success after failures" do
      counter = :counters.new(1, [:atomics])

      heartbeat_fn = fn _node ->
        count = :counters.get(counter, 1)
        :counters.add(counter, 1, 1)

        if count < 2 do
          {:error, :timeout}
        else
          {:ok, @primary_node}
        end
      end

      pid = start_monitor(heartbeat_fn)

      # Two failures
      send(pid, :heartbeat)
      :sys.get_state(pid)
      send(pid, :heartbeat)
      :sys.get_state(pid)

      # Now success
      send(pid, :heartbeat)
      state = :sys.get_state(pid)

      assert state.consecutive_failures == 0
      assert state.status == :connected
    end
  end

  describe "heartbeat failure" do
    test "increments consecutive failures" do
      pid = start_monitor(fn _node -> {:error, :timeout} end)

      send(pid, :heartbeat)
      state = :sys.get_state(pid)
      assert state.consecutive_failures == 1
      assert state.status == :connected

      send(pid, :heartbeat)
      state = :sys.get_state(pid)
      assert state.consecutive_failures == 2
      assert state.status == :connected
    end

    test "transitions to :unreachable after threshold failures" do
      pid = start_monitor(fn _node -> {:error, :timeout} end, failure_threshold: 3)

      for _ <- 1..3 do
        send(pid, :heartbeat)
        :sys.get_state(pid)
      end

      state = :sys.get_state(pid)
      assert state.status == :unreachable
      assert state.consecutive_failures == 3
    end

    test "does not re-notify on subsequent failures after unreachable" do
      pid = start_monitor(fn _node -> {:error, :timeout} end, failure_threshold: 2)

      # Reach unreachable
      send(pid, :heartbeat)
      :sys.get_state(pid)
      send(pid, :heartbeat)
      :sys.get_state(pid)

      assert :sys.get_state(pid).status == :unreachable

      # More failures should not change status (still unreachable)
      send(pid, :heartbeat)
      state = :sys.get_state(pid)
      assert state.status == :unreachable
      assert state.consecutive_failures == 3
    end
  end

  describe "recovery" do
    test "transitions back to :connected when heartbeat succeeds after unreachable" do
      counter = :counters.new(1, [:atomics])

      heartbeat_fn = fn _node ->
        count = :counters.get(counter, 1)
        :counters.add(counter, 1, 1)

        if count < 3 do
          {:error, :timeout}
        else
          {:ok, @primary_node}
        end
      end

      pid = start_monitor(heartbeat_fn, failure_threshold: 3)

      # 3 failures -> unreachable
      for _ <- 1..3 do
        send(pid, :heartbeat)
        :sys.get_state(pid)
      end

      assert :sys.get_state(pid).status == :unreachable

      # Success -> back to connected
      send(pid, :heartbeat)
      state = :sys.get_state(pid)
      assert state.status == :connected
      assert state.consecutive_failures == 0
    end
  end
end
