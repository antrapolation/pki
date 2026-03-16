defmodule PkiAuditTrail.AuditEventTest do
  use PkiAuditTrail.DataCase, async: true
  alias PkiAuditTrail.AuditEvent

  describe "changeset/2" do
    test "valid changeset with all required fields" do
      attrs = %{
        event_id: Ecto.UUID.generate(),
        timestamp: DateTime.utc_now(),
        node_name: "pki_ca_engine@localhost",
        actor_did: "did:ssdid:abc123",
        actor_role: "ca_admin",
        action: "certificate_issued",
        resource_type: "certificate",
        resource_id: "cert-001",
        details: %{"serial" => "ABC123"},
        prev_hash: String.duplicate("0", 64),
        event_hash: String.duplicate("a", 64)
      }
      changeset = AuditEvent.changeset(%AuditEvent{}, attrs)
      assert changeset.valid?
    end

    test "invalid changeset missing required fields" do
      changeset = AuditEvent.changeset(%AuditEvent{}, %{})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).action
      assert "can't be blank" in errors_on(changeset).event_id
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
