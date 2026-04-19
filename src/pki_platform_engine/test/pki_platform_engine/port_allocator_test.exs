defmodule PkiPlatformEngine.PortAllocatorTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.PortAllocator

  setup do
    # Start a fresh PortAllocator for each test (not registered globally)
    # We stop the globally-registered one first if running, then start our own.
    if pid = Process.whereis(PortAllocator) do
      GenServer.stop(pid)
    end

    {:ok, pid} = PortAllocator.start_link()
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
end
