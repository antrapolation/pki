defmodule PkiAuditTrail.WalBufferTest do
  use ExUnit.Case, async: false

  alias PkiAuditTrail.WalBuffer

  setup do
    :mnesia.clear_table(:audit_wal_buffer)
    :ok
  end

  test "replay_wal/0 flushes pending WAL entries that are not in Postgres" do
    # Write an event to WAL but do NOT flush it (simulates crash before flush)
    attrs = %{
      event_id: Ecto.UUID.generate(),
      timestamp: DateTime.utc_now(),
      node_name: "node1",
      actor_did: "did:ssdid:a",
      actor_role: "ca_admin",
      action: "login",
      resource_type: "session",
      resource_id: "s1",
      details: %{},
      prev_hash: String.duplicate("0", 64),
      event_hash: String.duplicate("a", 64)
    }

    {:ok, _wal_id} = WalBuffer.write(attrs)
    assert length(WalBuffer.pending()) == 1

    # Simulate startup replay — the event is not in Postgres so it gets discarded
    # We need a sandbox checkout for the Repo query
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(PkiAuditTrail.Repo, shared: true)

    PkiAuditTrail.Application.replay_wal()

    # WAL should be cleaned up
    assert WalBuffer.pending() == []

    Ecto.Adapters.SQL.Sandbox.stop_owner(pid)
  end

  test "write/1 stores event attrs in Mnesia and returns id" do
    attrs = %{
      event_id: Ecto.UUID.generate(),
      timestamp: DateTime.utc_now(),
      node_name: "node1",
      actor_did: "did:ssdid:a",
      actor_role: "ca_admin",
      action: "login",
      resource_type: "session",
      resource_id: "s1",
      details: %{},
      prev_hash: String.duplicate("0", 64),
      event_hash: String.duplicate("a", 64)
    }

    assert {:ok, _id} = WalBuffer.write(attrs)
    assert [{_, _id, _attrs}] = WalBuffer.pending()
  end

  test "flush/1 removes flushed events" do
    attrs = %{
      event_id: Ecto.UUID.generate(),
      timestamp: DateTime.utc_now(),
      node_name: "node1",
      actor_did: "did:ssdid:a",
      actor_role: "ca_admin",
      action: "login",
      resource_type: "session",
      resource_id: "s1",
      details: %{},
      prev_hash: String.duplicate("0", 64),
      event_hash: String.duplicate("a", 64)
    }

    {:ok, id} = WalBuffer.write(attrs)
    [{_, ^id, _}] = WalBuffer.pending()
    :ok = WalBuffer.flush(id)
    assert [] = WalBuffer.pending()
  end
end
