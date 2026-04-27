defmodule PkiAuditTrail.TenantLogTest do
  use PkiAuditTrail.DataCase, async: false

  @tenant_id "11111111-1111-1111-1111-111111111111"
  @prefix "t_11111111111111111111111111111111_audit"
  @genesis String.duplicate("0", 64)

  setup do
    Ecto.Adapters.SQL.query!(PkiAuditTrail.Repo, "CREATE SCHEMA IF NOT EXISTS \"#{@prefix}\"", [])
    Ecto.Adapters.SQL.query!(PkiAuditTrail.Repo, """
    CREATE TABLE IF NOT EXISTS "#{@prefix}".audit_events (
      id bigserial PRIMARY KEY,
      event_id uuid NOT NULL,
      "timestamp" timestamp(6) NOT NULL,
      node_name varchar(255) NOT NULL,
      actor_did varchar(255) NOT NULL,
      actor_role varchar(255) NOT NULL,
      action varchar(255) NOT NULL,
      resource_type varchar(255) NOT NULL,
      resource_id varchar(255) NOT NULL,
      details jsonb DEFAULT '{}',
      prev_hash varchar(64) NOT NULL,
      event_hash varchar(64) NOT NULL,
      ca_instance_id varchar(255)
    )
    """, [])

    # Ensure ETS cache is clean for this tenant between tests
    if :ets.info(:pki_audit_hash_chain) != :undefined do
      :ets.delete(:pki_audit_hash_chain, @tenant_id)
    end

    on_exit(fn ->
      Ecto.Adapters.SQL.query!(
        PkiAuditTrail.Repo,
        "DROP SCHEMA IF EXISTS \"#{@prefix}\" CASCADE",
        []
      )
    end)

    :ok
  end

  test "log/4 writes an event to the tenant audit schema" do
    actor = %{actor_did: "user:alice", actor_role: "ca_admin"}
    resource = %{resource_type: "certificate", resource_id: "cert-1", details: %{}}

    assert {:ok, event} = PkiAuditTrail.log(@tenant_id, actor, "certificate_issued", resource)
    assert event.actor_did == "user:alice"
    assert event.action == "certificate_issued"
    assert event.prev_hash == @genesis
  end

  test "second event's prev_hash equals first event's event_hash" do
    actor = %{actor_did: "user:bob", actor_role: "ca_admin"}
    r1 = %{resource_type: "certificate", resource_id: "c1", details: %{}}
    r2 = %{resource_type: "certificate", resource_id: "c2", details: %{}}

    {:ok, e1} = PkiAuditTrail.log(@tenant_id, actor, "certificate_issued", r1)
    {:ok, e2} = PkiAuditTrail.log(@tenant_id, actor, "certificate_revoked", r2)

    assert e2.prev_hash == e1.event_hash
  end

  test "log/4 returns {:error, ...} when table is missing — does not raise" do
    bad_tenant_id = "22222222-2222-2222-2222-222222222222"
    actor = %{actor_did: "system", actor_role: "system"}
    resource = %{resource_type: "test", resource_id: "x", details: %{}}

    result = PkiAuditTrail.log(bad_tenant_id, actor, "certificate_issued", resource)
    assert {:error, _} = result
  end

  test "Actions.valid?/1 returns true for portal action strings" do
    portal_actions = ~w[
      keystore_configured activation_lease_granted csr_submitted_via_portal
      dcv_started dcv_passed certificate_revoked ca_instance_created
      issuer_key_unlocked issuer_key_retired api_key_created profile_updated
      password_changed ceremony_initiated ceremony_key_generated hsm_wizard_completed
    ]

    for action <- portal_actions do
      assert PkiAuditTrail.Actions.valid?(action), "Expected #{action} to be valid"
    end
  end
end
