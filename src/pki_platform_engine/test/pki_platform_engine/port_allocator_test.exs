defmodule PkiPlatformEngine.PortAllocatorTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.PortAllocator

  setup do
    # Start a private, non-global PortAllocator with persist: false.
    # Do NOT stop the globally-registered one: it's a child of the
    # app's :rest_for_one supervisor with :permanent restart, so a
    # normal stop triggers a restart that races the test's re-start
    # under the same name — the restart loop exceeds max_restarts and
    # brings down PlatformRepo too.
    name = :"test_port_allocator_#{System.unique_integer([:positive])}"
    {:ok, pid} = PortAllocator.start_link(name: name, persist: false)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, allocator: name}
  end

  test "allocate assigns a port from the pool", %{allocator: a} do
    {:ok, port} = GenServer.call(a, {:allocate, "tenant-1"})
    assert port >= 5001
    assert port <= 5999
  end

  test "allocate returns same port for same tenant", %{allocator: a} do
    {:ok, port1} = GenServer.call(a, {:allocate, "tenant-1"})
    {:ok, port2} = GenServer.call(a, {:allocate, "tenant-1"})
    assert port1 == port2
  end

  test "allocate assigns different ports to different tenants", %{allocator: a} do
    {:ok, port1} = GenServer.call(a, {:allocate, "tenant-1"})
    {:ok, port2} = GenServer.call(a, {:allocate, "tenant-2"})
    assert port1 != port2
  end

  test "release frees a port", %{allocator: a} do
    {:ok, _port} = GenServer.call(a, {:allocate, "tenant-1"})
    :ok = GenServer.call(a, {:release, "tenant-1"})
    assert GenServer.call(a, {:get_port, "tenant-1"}) == nil
  end

  test "list_assignments shows all active assignments", %{allocator: a} do
    {:ok, _} = GenServer.call(a, {:allocate, "t1"})
    {:ok, _} = GenServer.call(a, {:allocate, "t2"})
    assignments = GenServer.call(a, :list)
    assert map_size(assignments) == 2
  end

  describe "pool exhaustion" do
    # Run these against a private, non-registered, PG-free allocator so
    # we can exhaust a tiny pool in milliseconds without hammering the
    # platform DB. The global name is reserved by the setup block above.
    setup do
      name = :"test_port_allocator_#{System.unique_integer([:positive])}"

      {:ok, pid} =
        PortAllocator.start_link(
          name: name,
          port_range: 5500..5502,
          persist: false
        )

      on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
      {:ok, allocator: name}
    end

    test "allocate returns :no_ports_available once the pool is full", %{allocator: alloc} do
      assert {:ok, 5500} = GenServer.call(alloc, {:allocate, "t1"})
      assert {:ok, 5501} = GenServer.call(alloc, {:allocate, "t2"})
      assert {:ok, 5502} = GenServer.call(alloc, {:allocate, "t3"})

      assert {:error, :no_ports_available} = GenServer.call(alloc, {:allocate, "t4"})
      assert {:error, :no_ports_available} = GenServer.call(alloc, {:allocate, "t5"})
    end

    test "releasing a port makes it available again", %{allocator: alloc} do
      {:ok, _} = GenServer.call(alloc, {:allocate, "t1"})
      {:ok, _} = GenServer.call(alloc, {:allocate, "t2"})
      {:ok, 5502} = GenServer.call(alloc, {:allocate, "t3"})
      {:error, :no_ports_available} = GenServer.call(alloc, {:allocate, "t4"})

      :ok = GenServer.call(alloc, {:release, "t2"})

      # The freed port (5501) is the lowest free, so t4 lands on it.
      assert {:ok, 5501} = GenServer.call(alloc, {:allocate, "t4"})
      assert {:error, :no_ports_available} = GenServer.call(alloc, {:allocate, "t5"})
    end

    test "re-allocating an already-assigned tenant never consumes a new port", %{allocator: alloc} do
      {:ok, 5500} = GenServer.call(alloc, {:allocate, "t1"})
      {:ok, 5501} = GenServer.call(alloc, {:allocate, "t2"})
      {:ok, 5502} = GenServer.call(alloc, {:allocate, "t3"})

      # t1 is already assigned — must return the same port, not error.
      assert {:ok, 5500} = GenServer.call(alloc, {:allocate, "t1"})
      assert {:error, :no_ports_available} = GenServer.call(alloc, {:allocate, "t4"})
    end

    test "release is idempotent — releasing twice is a no-op", %{allocator: alloc} do
      {:ok, _} = GenServer.call(alloc, {:allocate, "t1"})
      :ok = GenServer.call(alloc, {:release, "t1"})
      :ok = GenServer.call(alloc, {:release, "t1"})
      :ok = GenServer.call(alloc, {:release, "never-allocated"})

      assert GenServer.call(alloc, :list) == %{}
    end
  end
end
