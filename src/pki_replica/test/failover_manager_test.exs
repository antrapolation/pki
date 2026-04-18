defmodule PkiReplica.FailoverManagerTest do
  use ExUnit.Case, async: true

  alias PkiReplica.FailoverManager

  defp start_manager(opts \\ []) do
    name = :"fm_#{:erlang.unique_integer([:positive])}"

    promote_fn = Keyword.get(opts, :promote_fn, fn _slug -> :ok end)

    {:ok, pid} =
      GenServer.start_link(FailoverManager, [
        webhook_url: nil,
        alert_log_path: Path.join(System.tmp_dir!(), "pki_test_failover_#{name}.log"),
        promote_fn: promote_fn
      ], name: name)

    pid
  end

  describe "initial state" do
    test "starts with :normal status" do
      pid = start_manager()
      assert GenServer.call(pid, :status) == :normal
    end
  end

  describe "primary_unreachable notification" do
    test "transitions from :normal to :primary_down" do
      pid = start_manager()
      GenServer.cast(pid, {:primary_unreachable})
      # Let the cast process
      assert GenServer.call(pid, :status) == :primary_down
    end

    test "ignores duplicate unreachable notifications" do
      pid = start_manager()
      GenServer.cast(pid, {:primary_unreachable})
      assert GenServer.call(pid, :status) == :primary_down

      # Second notification should not change state
      GenServer.cast(pid, {:primary_unreachable})
      assert GenServer.call(pid, :status) == :primary_down
    end
  end

  describe "promote_all/0" do
    test "rejects promotion when status is :normal" do
      pid = start_manager()
      assert GenServer.call(pid, :promote_all) == {:error, :primary_not_down}
    end

    test "promotes and returns tenant list when primary is down" do
      pid = start_manager()
      GenServer.cast(pid, {:primary_unreachable})
      assert GenServer.call(pid, :status) == :primary_down

      # promote_all with empty tenant list (default list_replica_tenants returns [])
      assert {:ok, []} = GenServer.call(pid, :promote_all)
      assert GenServer.call(pid, :status) == :promoted
    end

    test "returns already promoted tenants when called again" do
      pid = start_manager()
      GenServer.cast(pid, {:primary_unreachable})
      {:ok, _} = GenServer.call(pid, :promote_all)

      # Call again — should return same list
      assert {:ok, []} = GenServer.call(pid, :promote_all)
    end
  end

  describe "promote_tenant/1" do
    test "rejects single promotion when status is :normal" do
      pid = start_manager()
      assert GenServer.call(pid, {:promote_tenant, "acme"}) == {:error, :primary_not_down}
    end

    test "promotes a single tenant when primary is down" do
      pid = start_manager(promote_fn: fn _slug -> :ok end)
      GenServer.cast(pid, {:primary_unreachable})
      assert GenServer.call(pid, :status) == :primary_down

      assert :ok = GenServer.call(pid, {:promote_tenant, "acme"})
      assert GenServer.call(pid, :status) == :promoted

      state = :sys.get_state(pid)
      assert "acme" in state.promoted_tenants
    end

    test "handles promotion failure gracefully" do
      pid = start_manager(promote_fn: fn _slug -> {:error, :mnesia_down} end)
      GenServer.cast(pid, {:primary_unreachable})

      assert {:error, :mnesia_down} = GenServer.call(pid, {:promote_tenant, "acme"})
    end
  end

  describe "state transitions" do
    test "full lifecycle: normal -> primary_down -> promoting -> promoted" do
      pid = start_manager(promote_fn: fn _slug -> :ok end)

      assert GenServer.call(pid, :status) == :normal

      GenServer.cast(pid, {:primary_unreachable})
      assert GenServer.call(pid, :status) == :primary_down

      {:ok, _} = GenServer.call(pid, :promote_all)
      assert GenServer.call(pid, :status) == :promoted
    end
  end
end
