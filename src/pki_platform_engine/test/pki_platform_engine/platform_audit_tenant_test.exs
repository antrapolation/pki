defmodule PkiPlatformEngine.PlatformAuditTenantTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.{PlatformAudit, Provisioner, TenantPrefix, PlatformRepo}
  import Ecto.Query

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(PlatformRepo)
    Ecto.Adapters.SQL.Sandbox.mode(PlatformRepo, :auto)
    :ok
  end

  test "PlatformAudit.log writes to per-tenant audit_events for schema-mode tenant" do
    slug = "audit-wire-#{System.unique_integer([:positive])}"
    {:ok, tenant} = Provisioner.create_tenant("Audit Wire Test", slug,
      schema_mode: "schema", email: "auditw@example.com")
    on_exit(fn -> Provisioner.delete_tenant(tenant.id) end)

    PlatformAudit.log("cert_issued", %{
      tenant_id: tenant.id,
      actor_id: Ecto.UUID.generate(),
      actor_username: "alice",
      actor_role: "ca_admin",
      target_type: "certificate",
      target_id: Ecto.UUID.generate(),
      portal: "ca"
    })

    prefix = TenantPrefix.audit_prefix(tenant.id)
    {:ok, result} = Ecto.Adapters.SQL.query(
      PlatformRepo,
      "SELECT action, actor_did FROM \"#{prefix}\".audit_events WHERE action = 'cert_issued'",
      []
    )
    assert length(result.rows) == 1
    [[action, actor_did]] = result.rows
    assert action == "cert_issued"
    assert actor_did == "alice"
  end

  test "PlatformAudit.log does not crash for beam-mode tenant" do
    {:ok, beam_tenant} = Provisioner.register_tenant(
      "Beam Tenant",
      "beam-#{System.unique_integer([:positive])}",
      email: "beam@example.com"
    )
    on_exit(fn ->
      PlatformRepo.delete_all(from t in PkiPlatformEngine.Tenant, where: t.id == ^beam_tenant.id)
    end)

    result = PlatformAudit.log("cert_issued", %{
      tenant_id: beam_tenant.id,
      actor_id: Ecto.UUID.generate(),
      actor_username: "bob",
      target_type: "certificate",
      target_id: Ecto.UUID.generate(),
      portal: "ca"
    })

    assert {:ok, _} = result
  end

  test "PlatformAudit.log succeeds when no tenant_id in attrs" do
    # system action, no actor or tenant required
    result = PlatformAudit.log("session_expired", %{portal: "ca"})
    assert {:ok, _} = result
  end
end
