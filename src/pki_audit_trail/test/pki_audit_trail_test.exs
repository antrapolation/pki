defmodule PkiAuditTrailTest do
  use PkiAuditTrail.DataCase, async: false

  setup do
    PkiAuditTrail.Logger.reset()
    :ok
  end

  describe "log/3" do
    test "delegates to Logger and returns event" do
      {:ok, event} =
        PkiAuditTrail.log(
          %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
          "key_generated",
          %{resource_type: "issuer_key", resource_id: "key-001", details: %{"algo" => "ML-DSA-65"}}
        )

      assert event.action == "key_generated"
      assert event.details == %{"algo" => "ML-DSA-65"}
    end
  end

  describe "verify_chain/0" do
    test "delegates to Verifier" do
      assert {:ok, 0} = PkiAuditTrail.verify_chain()
    end
  end

  describe "query/1" do
    test "filters events by action" do
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "login",
        %{resource_type: "session", resource_id: "s1"}
      )
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "certificate_issued",
        %{resource_type: "certificate", resource_id: "c1"}
      )

      events = PkiAuditTrail.query(action: "login")
      assert length(events) == 1
      assert hd(events).action == "login"
    end

    test "filters events by actor_did" do
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "login",
        %{resource_type: "session", resource_id: "s1"}
      )
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:b", actor_role: "key_manager", node_name: "n1"},
        "login",
        %{resource_type: "session", resource_id: "s2"}
      )

      events = PkiAuditTrail.query(actor_did: "did:ssdid:b")
      assert length(events) == 1
      assert hd(events).actor_did == "did:ssdid:b"
    end

    test "filters by resource_type and resource_id" do
      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:a", actor_role: "ca_admin", node_name: "n1"},
        "certificate_issued",
        %{resource_type: "certificate", resource_id: "cert-001"}
      )

      events = PkiAuditTrail.query(resource_type: "certificate", resource_id: "cert-001")
      assert length(events) == 1
    end
  end

  describe "query/1 with date-range filters" do
    test "filters events by :since" do
      PkiAuditTrail.log(%{actor_did: "did:a", actor_role: "ca_admin", node_name: "n1"}, "login", %{resource_type: "session", resource_id: "s1"})
      Process.sleep(10)
      cutoff = DateTime.utc_now()
      Process.sleep(10)
      PkiAuditTrail.log(%{actor_did: "did:a", actor_role: "ca_admin", node_name: "n1"}, "logout", %{resource_type: "session", resource_id: "s1"})

      events = PkiAuditTrail.query(since: cutoff)
      assert length(events) == 1
      assert hd(events).action == "logout"
    end

    test "filters events by :until" do
      PkiAuditTrail.log(%{actor_did: "did:a", actor_role: "ca_admin", node_name: "n1"}, "login", %{resource_type: "session", resource_id: "s1"})
      Process.sleep(10)
      cutoff = DateTime.utc_now()
      Process.sleep(10)
      PkiAuditTrail.log(%{actor_did: "did:a", actor_role: "ca_admin", node_name: "n1"}, "logout", %{resource_type: "session", resource_id: "s1"})

      events = PkiAuditTrail.query(until: cutoff)
      assert length(events) == 1
      assert hd(events).action == "login"
    end

    test "combines :since and :until" do
      PkiAuditTrail.log(%{actor_did: "did:a", actor_role: "ca_admin", node_name: "n1"}, "login", %{resource_type: "session", resource_id: "s1"})
      Process.sleep(10)
      t1 = DateTime.utc_now()
      Process.sleep(10)
      PkiAuditTrail.log(%{actor_did: "did:a", actor_role: "ca_admin", node_name: "n1"}, "key_generated", %{resource_type: "key", resource_id: "k1"})
      Process.sleep(10)
      t2 = DateTime.utc_now()
      Process.sleep(10)
      PkiAuditTrail.log(%{actor_did: "did:a", actor_role: "ca_admin", node_name: "n1"}, "logout", %{resource_type: "session", resource_id: "s1"})

      events = PkiAuditTrail.query(since: t1, until: t2)
      assert length(events) == 1
      assert hd(events).action == "key_generated"
    end
  end
end
