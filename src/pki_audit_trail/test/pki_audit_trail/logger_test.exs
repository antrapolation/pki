defmodule PkiAuditTrail.LoggerTest do
  use PkiAuditTrail.DataCase, async: false

  alias PkiAuditTrail.{AuditEvent, Logger, Hasher}

  setup do
    # Reset the Logger GenServer state so it re-reads the last hash from
    # the (now-sandboxed) database, ensuring a clean chain per test.
    Logger.reset()
    :ok
  end

  describe "log/3" do
    test "inserts an audit event with correct hash chain" do
      {:ok, event} =
        Logger.log(
          %{
            actor_did: "did:ssdid:admin1",
            actor_role: "ca_admin",
            node_name: "pki_ca_engine@localhost"
          },
          "user_created",
          %{resource_type: "user", resource_id: "user-001", details: %{"role" => "key_manager"}}
        )

      assert event.action == "user_created"
      assert event.actor_did == "did:ssdid:admin1"
      assert event.prev_hash == Hasher.genesis_hash()
      assert String.length(event.event_hash) == 64

      # Verify hash is correctly computed
      expected_hash =
        Hasher.compute_hash(%{
          event_id: event.event_id,
          timestamp: event.timestamp,
          node_name: event.node_name,
          actor_did: event.actor_did,
          action: event.action,
          resource_type: event.resource_type,
          resource_id: event.resource_id,
          details: event.details,
          prev_hash: event.prev_hash
        })

      assert event.event_hash == expected_hash
    end

    test "second event chains to the first" do
      {:ok, first} =
        Logger.log(
          %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
          "login",
          %{resource_type: "session", resource_id: "s1"}
        )

      {:ok, second} =
        Logger.log(
          %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
          "user_created",
          %{resource_type: "user", resource_id: "u1"}
        )

      assert second.prev_hash == first.event_hash
    end

    test "events are append-only — count increases" do
      for i <- 1..3 do
        {:ok, _} =
          Logger.log(
            %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
            "login",
            %{resource_type: "session", resource_id: "r#{i}"}
          )
      end

      assert Repo.aggregate(AuditEvent, :count) == 3
    end
  end
end
