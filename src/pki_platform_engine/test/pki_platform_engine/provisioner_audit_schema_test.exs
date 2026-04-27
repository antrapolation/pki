defmodule PkiPlatformEngine.ProvisionerAuditSchemaTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.{Provisioner, TenantPrefix, PlatformRepo}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(PlatformRepo)
    Ecto.Adapters.SQL.Sandbox.mode(PlatformRepo, :auto)
    :ok
  end

  test "schema-mode provisioning creates audit_events table in audit prefix" do
    slug = "test-audit-#{System.unique_integer([:positive])}"
    {:ok, tenant} = Provisioner.create_tenant("Test Audit Tenant", slug, schema_mode: "schema", email: "audit@example.com")
    on_exit(fn -> Provisioner.delete_tenant(tenant.id) end)

    prefix = TenantPrefix.audit_prefix(tenant.id)
    {:ok, result} = PlatformRepo.query(
      "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'audit_events'",
      [prefix]
    )
    assert [[1]] = result.rows
  end

  test "schema-mode provisioning creates validation tables" do
    slug = "test-val-#{System.unique_integer([:positive])}"
    {:ok, tenant} = Provisioner.create_tenant("Test Val Tenant", slug, schema_mode: "schema", email: "val@example.com")
    on_exit(fn -> Provisioner.delete_tenant(tenant.id) end)

    prefix = TenantPrefix.validation_prefix(tenant.id)
    {:ok, result} = PlatformRepo.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY table_name",
      [prefix]
    )
    table_names = Enum.map(result.rows, &List.first/1)
    assert "certificate_status" in table_names
    assert "crl_metadata" in table_names
    assert "signing_key_config" in table_names
  end

  test "delete_tenant cleans up all four schemas" do
    slug = "test-cleanup-#{System.unique_integer([:positive])}"
    {:ok, tenant} = Provisioner.create_tenant("Test Cleanup", slug, schema_mode: "schema", email: "cleanup@example.com")
    prefixes = TenantPrefix.all_prefixes(tenant.id)

    Provisioner.delete_tenant(tenant.id)

    all_prefixes = Map.values(prefixes)
    {:ok, result} = PlatformRepo.query(
      "SELECT schema_name FROM information_schema.schemata WHERE schema_name = ANY($1)",
      [all_prefixes]
    )
    assert result.rows == []
  end
end
