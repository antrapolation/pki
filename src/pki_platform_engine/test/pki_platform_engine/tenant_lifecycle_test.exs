defmodule PkiPlatformEngine.TenantLifecycleTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.TenantLifecycle

  setup do
    # Start PortAllocator if not already running
    unless Process.whereis(PkiPlatformEngine.PortAllocator) do
      {:ok, _} = PkiPlatformEngine.PortAllocator.start_link()
    end

    # Start TenantLifecycle if not already running
    unless Process.whereis(TenantLifecycle) do
      {:ok, _} = TenantLifecycle.start_link()
    end

    :ok
  end

  test "starts with empty tenant list" do
    assert TenantLifecycle.list_tenants() == []
  end

  test "get_tenant returns not_found for unknown tenant" do
    assert TenantLifecycle.get_tenant("nonexistent") == {:error, :not_found}
  end
end
