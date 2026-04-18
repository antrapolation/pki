defmodule PkiReplica.TenantReplicaSupervisorTest do
  use ExUnit.Case, async: true

  alias PkiReplica.TenantReplicaSupervisor

  @primary_node :"pki_platform@test"

  # Starts a supervisor with spawn_replicas: false and a no-op spawn_fn.
  # poll_interval_ms is set to 1 hour so no background polls run during tests.
  defp start_supervisor(opts \\ []) do
    name = :"trs_#{:erlang.unique_integer([:positive])}"

    merged = [
      primary_node: Keyword.get(opts, :primary_node, @primary_node),
      poll_interval_ms: Keyword.get(opts, :poll_interval_ms, :timer.hours(1)),
      spawn_replicas: Keyword.get(opts, :spawn_replicas, false),
      spawn_fn: Keyword.get(opts, :spawn_fn, fn _slug, _node -> {:ok, %{peer_pid: nil, node: nil}} end),
      name: name
    ]

    {:ok, pid} = TenantReplicaSupervisor.start_link(merged)
    {pid, name}
  end

  describe "list_replicas/1" do
    test "returns empty map on fresh start" do
      {pid, name} = start_supervisor()

      assert TenantReplicaSupervisor.list_replicas(name) == %{}

      GenServer.stop(pid)
    end
  end

  describe "get_replica/2" do
    test "returns nil for unknown slug" do
      {pid, name} = start_supervisor()

      assert TenantReplicaSupervisor.get_replica("nonexistent", name) == nil

      GenServer.stop(pid)
    end
  end

  describe "handle_cast :tenant_started" do
    test "adds tenant to known_tenants" do
      {pid, name} = start_supervisor()

      GenServer.cast(
        name,
        {:tenant_started, %{tenant_id: "t1", slug: "acme", node: :"tenant_acme@server1"}}
      )

      # Use call to synchronise — known_tenants is checked via sys.get_state
      _replicas = TenantReplicaSupervisor.list_replicas(name)
      state = :sys.get_state(pid)

      assert Map.has_key?(state.known_tenants, "t1")
      assert state.known_tenants["t1"].slug == "acme"

      GenServer.stop(pid)
    end

    test "does not spawn when spawn_replicas is false" do
      {pid, name} = start_supervisor(spawn_replicas: false)

      GenServer.cast(
        name,
        {:tenant_started, %{tenant_id: "t2", slug: "beta", node: :"tenant_beta@server1"}}
      )

      _replicas = TenantReplicaSupervisor.list_replicas(name)
      state = :sys.get_state(pid)

      assert Map.has_key?(state.known_tenants, "t2")
      assert state.replicas == %{}

      GenServer.stop(pid)
    end

    test "spawns replica when spawn_replicas is true" do
      test_pid = self()
      ref = make_ref()

      spawn_fn = fn slug, primary_tenant_node ->
        send(test_pid, {ref, :spawned, slug, primary_tenant_node})
        {:ok, %{peer_pid: spawn(fn -> :timer.sleep(:infinity) end), node: :"tenant_#{slug}_replica@test"}}
      end

      {pid, name} = start_supervisor(spawn_replicas: true, spawn_fn: spawn_fn)

      GenServer.cast(
        name,
        {:tenant_started, %{tenant_id: "t3", slug: "gamma", node: :"tenant_gamma@server1"}}
      )

      # Wait for spawn notification
      assert_receive {^ref, :spawned, "gamma", :"tenant_gamma@server1"}, 500

      _replicas = TenantReplicaSupervisor.list_replicas(name)
      state = :sys.get_state(pid)

      assert Map.has_key?(state.replicas, "gamma")
      assert state.replicas["gamma"].status == :running

      GenServer.stop(pid)
    end

    test "does not spawn duplicate if replica already running" do
      test_pid = self()
      ref = make_ref()
      counter = :counters.new(1, [:atomics])

      spawn_fn = fn slug, _node ->
        :counters.add(counter, 1, 1)
        send(test_pid, {ref, :spawned, slug})
        {:ok, %{peer_pid: spawn(fn -> :timer.sleep(:infinity) end), node: :"tenant_#{slug}_replica@test"}}
      end

      {pid, name} = start_supervisor(spawn_replicas: true, spawn_fn: spawn_fn)

      # Start same tenant twice
      GenServer.cast(
        name,
        {:tenant_started, %{tenant_id: "t4", slug: "delta", node: :"tenant_delta@server1"}}
      )

      assert_receive {^ref, :spawned, "delta"}, 500

      GenServer.cast(
        name,
        {:tenant_started, %{tenant_id: "t4", slug: "delta", node: :"tenant_delta@server1"}}
      )

      # Synchronise
      _replicas = TenantReplicaSupervisor.list_replicas(name)

      assert :counters.get(counter, 1) == 1

      GenServer.stop(pid)
    end
  end

  describe "handle_cast :tenant_stopped" do
    test "removes tenant from known_tenants" do
      {pid, name} = start_supervisor()

      GenServer.cast(
        name,
        {:tenant_started, %{tenant_id: "t5", slug: "echo", node: :"tenant_echo@server1"}}
      )

      _replicas = TenantReplicaSupervisor.list_replicas(name)
      state = :sys.get_state(pid)
      assert Map.has_key?(state.known_tenants, "t5")

      GenServer.cast(name, {:tenant_stopped, %{tenant_id: "t5"}})
      _replicas = TenantReplicaSupervisor.list_replicas(name)
      state = :sys.get_state(pid)

      refute Map.has_key?(state.known_tenants, "t5")

      GenServer.stop(pid)
    end

    test "removes replica entry when tenant stops" do
      # Use spawn_replicas: false so no real peer is spawned — instead we manually
      # inject a replica entry into state via :sys.replace_state to avoid :peer.stop
      # blocking on a fake peer pid.
      {pid, name} = start_supervisor(spawn_replicas: false)

      # Populate known_tenants via the cast
      GenServer.cast(
        name,
        {:tenant_started, %{tenant_id: "t6", slug: "foxtrot", node: :"tenant_foxtrot@server1"}}
      )

      # Synchronise: use list_replicas call to drain the mailbox
      _replicas = TenantReplicaSupervisor.list_replicas(name)

      # Manually inject a replica entry (simulating one that was spawned)
      :sys.replace_state(pid, fn state ->
        replica_info = %{slug: "foxtrot", peer_pid: nil, node: nil, status: :running}
        %{state | replicas: Map.put(state.replicas, "foxtrot", replica_info)}
      end)

      # Now stop the tenant
      GenServer.cast(name, {:tenant_stopped, %{tenant_id: "t6"}})
      _replicas = TenantReplicaSupervisor.list_replicas(name)
      state = :sys.get_state(pid)

      refute Map.has_key?(state.replicas, "foxtrot")

      GenServer.stop(pid)
    end

    test "ignores stop for unknown tenant_id" do
      {pid, name} = start_supervisor()

      GenServer.cast(name, {:tenant_stopped, %{tenant_id: "unknown"}})
      state = :sys.get_state(pid)

      assert state.known_tenants == %{}

      GenServer.stop(pid)
    end
  end

  describe "promote_tenant/2" do
    test "returns error when tenant not found" do
      {pid, name} = start_supervisor()

      assert TenantReplicaSupervisor.promote_tenant("nonexistent", name) == {:error, :not_found}

      GenServer.stop(pid)
    end
  end

  describe "demote_tenant/2" do
    test "returns error when tenant not found" do
      {pid, name} = start_supervisor()

      assert TenantReplicaSupervisor.demote_tenant("nonexistent", name) == {:error, :not_found}

      GenServer.stop(pid)
    end
  end

  describe "unreachable primary on boot" do
    test "starts successfully even if primary is unreachable" do
      {pid, name} =
        start_supervisor(
          primary_node: :"nonexistent@127.0.0.1",
          spawn_replicas: false
        )

      assert TenantReplicaSupervisor.list_replicas(name) == %{}

      GenServer.stop(pid)
    end
  end
end
