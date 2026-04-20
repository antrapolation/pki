defmodule PkiPlatformEngine.TenantRegistryTest do
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.TenantRegistry

  setup do
    registry = start_supervised!({TenantRegistry, name: :"test_registry_#{System.unique_integer([:positive])}"})
    %{registry: registry}
  end

  test "register and lookup tenant", %{registry: registry} do
    tenant_id = "tenant-1"
    refs = %{ca_repo: self(), ra_repo: self(), audit_repo: self(), slug: "test-corp"}

    :ok = TenantRegistry.register(registry, tenant_id, refs)
    assert {:ok, ^refs} = TenantRegistry.lookup(registry, tenant_id)
  end

  test "lookup_by_slug returns tenant refs", %{registry: registry} do
    tenant_id = "tenant-2"
    refs = %{ca_repo: self(), ra_repo: self(), audit_repo: self(), slug: "slug-corp"}

    :ok = TenantRegistry.register(registry, tenant_id, refs)
    assert {:ok, ^refs} = TenantRegistry.lookup_by_slug(registry, "slug-corp")
  end

  test "lookup returns error for unregistered tenant", %{registry: registry} do
    assert {:error, :not_found} = TenantRegistry.lookup(registry, "unknown")
  end

  test "unregister removes tenant", %{registry: registry} do
    :ok = TenantRegistry.register(registry, "t1", %{ca_repo: self(), ra_repo: self(), audit_repo: self(), slug: "s1"})
    :ok = TenantRegistry.unregister(registry, "t1")
    assert {:error, :not_found} = TenantRegistry.lookup(registry, "t1")
  end

  test "unregister removes slug index", %{registry: registry} do
    :ok = TenantRegistry.register(registry, "t1", %{ca_repo: self(), slug: "s1"})
    :ok = TenantRegistry.unregister(registry, "t1")
    assert {:error, :not_found} = TenantRegistry.lookup_by_slug(registry, "s1")
  end

  test "list_tenants returns all registered", %{registry: registry} do
    :ok = TenantRegistry.register(registry, "t1", %{slug: "a"})
    :ok = TenantRegistry.register(registry, "t2", %{slug: "b"})
    tenants = TenantRegistry.list_tenants(registry)
    assert length(tenants) == 2
  end

end
