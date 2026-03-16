defmodule PkiAuditTrail.HasherTest do
  use ExUnit.Case, async: true
  alias PkiAuditTrail.Hasher

  describe "compute_hash/1" do
    test "produces a 64-char hex string (SHA3-256)" do
      attrs = %{
        event_id: "550e8400-e29b-41d4-a716-446655440000",
        timestamp: ~U[2026-03-15 12:00:00.000000Z],
        node_name: "pki_ca_engine@localhost",
        actor_did: "did:ssdid:abc123",
        action: "certificate_issued",
        resource_type: "certificate",
        resource_id: "cert-001",
        details: %{"serial" => "ABC123"},
        prev_hash: String.duplicate("0", 64)
      }
      hash = Hasher.compute_hash(attrs)
      assert is_binary(hash)
      assert String.length(hash) == 64
      assert Regex.match?(~r/^[0-9a-f]{64}$/, hash)
    end

    test "same input produces same hash (deterministic)" do
      attrs = %{
        event_id: "550e8400-e29b-41d4-a716-446655440000",
        timestamp: ~U[2026-03-15 12:00:00.000000Z],
        node_name: "node1",
        actor_did: "did:ssdid:abc",
        action: "login",
        resource_type: "session",
        resource_id: "s1",
        details: %{},
        prev_hash: String.duplicate("0", 64)
      }
      assert Hasher.compute_hash(attrs) == Hasher.compute_hash(attrs)
    end

    test "different input produces different hash" do
      base = %{
        event_id: "550e8400-e29b-41d4-a716-446655440000",
        timestamp: ~U[2026-03-15 12:00:00.000000Z],
        node_name: "node1",
        actor_did: "did:ssdid:abc",
        action: "login",
        resource_type: "session",
        resource_id: "s1",
        details: %{},
        prev_hash: String.duplicate("0", 64)
      }
      modified = %{base | action: "logout"}
      refute Hasher.compute_hash(base) == Hasher.compute_hash(modified)
    end
  end

  describe "genesis_hash/0" do
    test "returns 64 zeroes" do
      assert Hasher.genesis_hash() == String.duplicate("0", 64)
    end
  end
end
