defmodule PkiAuditTrail.VerifierTest do
  use PkiAuditTrail.DataCase, async: false

  alias PkiAuditTrail.{Logger, Verifier, Repo, AuditEvent}

  setup do
    Logger.reset()
    :ok
  end

  defp log_event(action \\ "login", resource_id) do
    {:ok, event} =
      Logger.log(
        %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
        action,
        %{resource_type: "test", resource_id: resource_id}
      )
    event
  end

  describe "verify_chain/0" do
    test "empty chain is valid" do
      assert {:ok, 0} = Verifier.verify_chain()
    end

    test "single event chain is valid" do
      log_event("login", "s1")
      assert {:ok, 1} = Verifier.verify_chain()
    end

    test "multi-event chain is valid" do
      for i <- 1..5, do: log_event("login", "r#{i}")
      assert {:ok, 5} = Verifier.verify_chain()
    end

    test "detects tampered event_hash" do
      event = log_event("login", "s1")

      Repo.update_all(
        from(e in AuditEvent, where: e.id == ^event.id),
        set: [event_hash: String.duplicate("f", 64)]
      )

      assert {:error, {:tampered_hash, _event_id}} = Verifier.verify_chain()
    end

    test "detects broken chain link" do
      log_event("login", "r1")
      event2 = log_event("logout", "r2")

      Repo.update_all(
        from(e in AuditEvent, where: e.id == ^event2.id),
        set: [prev_hash: String.duplicate("b", 64)]
      )

      assert {:error, {:broken_chain, _event_id}} = Verifier.verify_chain()
    end
  end
end
