defmodule PkiPlatformEngine.TenantProcessTest do
  use ExUnit.Case

  alias PkiPlatformEngine.{TenantProcess, TenantRegistry}

  @tag :integration
  @tag :legacy_db_mode
  test "starts and registers repos for a tenant" do
    suffix = System.unique_integer([:positive])
    registry_name = :"test_reg_tp_#{suffix}"

    start_supervised!({TenantRegistry, name: registry_name})

    tenant = %{
      id: "test-tenant-#{suffix}",
      slug: "test-slug-#{suffix}",
      database_name: "pki_platform_dev"
    }

    {:ok, pid} = TenantProcess.start_link(tenant: tenant, registry: registry_name)
    assert Process.alive?(pid)

    # Verify repos are registered
    {:ok, refs} = TenantRegistry.lookup(registry_name, tenant.id)
    assert refs.ca_repo == :"ca_repo_#{tenant.id}"
    assert refs.ra_repo == :"ra_repo_#{tenant.id}"
    assert refs.audit_repo == :"audit_repo_#{tenant.id}"
    assert refs.slug == tenant.slug

    # Verify repos are actually running (named processes)
    assert Process.whereis(refs.ca_repo) != nil
    assert Process.whereis(refs.ra_repo) != nil
    assert Process.whereis(refs.audit_repo) != nil

    # Clean up
    Supervisor.stop(pid)
  end
end
