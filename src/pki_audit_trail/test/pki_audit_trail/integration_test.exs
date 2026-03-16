defmodule PkiAuditTrail.IntegrationTest do
  use PkiAuditTrail.DataCase, async: false

  setup do
    PkiAuditTrail.Logger.reset()
    :ok
  end

  @admin %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "pki_ca_engine@localhost"}
  @keymgr %{actor_did: "did:ssdid:keymgr1", actor_role: "key_manager", node_name: "pki_ca_engine@localhost"}

  test "full ceremony lifecycle produces valid chain" do
    {:ok, _} = PkiAuditTrail.log(@admin, "login", %{resource_type: "session", resource_id: "s1"})
    {:ok, _} = PkiAuditTrail.log(@admin, "ceremony_started", %{resource_type: "ceremony", resource_id: "cer-001", details: %{"algorithm" => "ML-DSA-65", "threshold" => "3-of-5"}})
    {:ok, _} = PkiAuditTrail.log(@keymgr, "key_generated", %{resource_type: "issuer_key", resource_id: "key-001", details: %{"algorithm" => "ML-DSA-65"}})
    {:ok, _} = PkiAuditTrail.log(@admin, "ceremony_completed", %{resource_type: "ceremony", resource_id: "cer-001"})
    {:ok, _} = PkiAuditTrail.log(@keymgr, "key_activated", %{resource_type: "issuer_key", resource_id: "key-001"})
    {:ok, _} = PkiAuditTrail.log(@admin, "logout", %{resource_type: "session", resource_id: "s1"})

    assert {:ok, 6} = PkiAuditTrail.verify_chain()

    ceremony_events = PkiAuditTrail.query(action: "ceremony_started")
    assert length(ceremony_events) == 1
    assert hd(ceremony_events).details["algorithm"] == "ML-DSA-65"

    keymgr_events = PkiAuditTrail.query(actor_did: "did:ssdid:keymgr1")
    assert length(keymgr_events) == 2

    key_events = PkiAuditTrail.query(resource_type: "issuer_key", resource_id: "key-001")
    assert length(key_events) == 2
  end

  test "invalid action is rejected" do
    assert {:error, {:invalid_action, "bogus"}} =
             PkiAuditTrail.log(@admin, "bogus", %{resource_type: "test", resource_id: "t1"})
  end
end
