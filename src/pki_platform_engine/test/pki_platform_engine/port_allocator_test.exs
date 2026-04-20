defmodule PkiPlatformEngine.PortAllocatorTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.PortAllocator

  setup do
    # Start a fresh PortAllocator for each test (not registered globally).
    # Stop the globally-registered one first if running, then start our own
    # with persist: false — these unit tests don't care about Postgres
    # persistence and using string tenant IDs like "tenant-1" would fail
    # the UUID cast anyway.
    if pid = Process.whereis(PortAllocator) do
      GenServer.stop(pid)
    end

    {:ok, pid} = PortAllocator.start_link(persist: false)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    :ok
  end

  test "allocate assigns a port from the pool" do
    {:ok, port} = PortAllocator.allocate("tenant-1")
    assert port >= 5001
    assert port <= 5999
  end

  test "allocate returns same port for same tenant" do
    {:ok, port1} = PortAllocator.allocate("tenant-1")
    {:ok, port2} = PortAllocator.allocate("tenant-1")
    assert port1 == port2
  end

  test "allocate assigns different ports to different tenants" do
    {:ok, port1} = PortAllocator.allocate("tenant-1")
    {:ok, port2} = PortAllocator.allocate("tenant-2")
    assert port1 != port2
  end

  test "release frees a port" do
    {:ok, _port} = PortAllocator.allocate("tenant-1")
    :ok = PortAllocator.release("tenant-1")
    assert PortAllocator.get_port("tenant-1") == nil
  end

  test "list_assignments shows all active assignments" do
    {:ok, _} = PortAllocator.allocate("t1")
    {:ok, _} = PortAllocator.allocate("t2")
    assignments = PortAllocator.list_assignments()
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
