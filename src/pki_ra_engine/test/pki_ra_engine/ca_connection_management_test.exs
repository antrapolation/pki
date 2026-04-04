defmodule PkiRaEngine.CaConnectionManagementTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.CaConnectionManagement
  alias PkiRaEngine.RaInstanceManagement

  setup do
    {:ok, ra} =
      RaInstanceManagement.create_ra_instance(nil, %{name: "test-ra-#{System.unique_integer([:positive])}", created_by: "admin"})

    {:ok, ra: ra}
  end

  describe "connect/3" do
    test "creates a new CA connection", %{ra: ra} do
      attrs = %{
        issuer_key_id: "issuer-key-001",
        issuer_key_name: "Test Issuer",
        algorithm: "ML-DSA-65",
        ca_instance_name: "Root CA"
      }

      assert {:ok, conn} = CaConnectionManagement.connect(nil, ra.id, attrs)
      assert conn.ra_instance_id == ra.id
      assert conn.issuer_key_id == "issuer-key-001"
      assert conn.issuer_key_name == "Test Issuer"
      assert conn.algorithm == "ML-DSA-65"
      assert conn.ca_instance_name == "Root CA"
      assert conn.status == "active"
      assert conn.connected_at != nil
    end

    test "prevents duplicate connections for same ra_instance + issuer_key", %{ra: ra} do
      attrs = %{issuer_key_id: "issuer-key-dup", issuer_key_name: "Dup Key"}

      assert {:ok, _conn} = CaConnectionManagement.connect(nil, ra.id, attrs)
      assert {:error, changeset} = CaConnectionManagement.connect(nil, ra.id, attrs)
      assert errors_on(changeset)[:ra_instance_id] != nil || errors_on(changeset)[:issuer_key_id] != nil
    end
  end

  describe "disconnect/2" do
    test "revokes an active connection", %{ra: ra} do
      {:ok, conn} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-to-revoke"})

      assert {:ok, revoked} = CaConnectionManagement.disconnect(nil, conn.id)
      assert revoked.status == "revoked"
    end

    test "returns not_found for missing connection" do
      assert {:error, :not_found} = CaConnectionManagement.disconnect(nil, Uniq.UUID.uuid7())
    end
  end

  describe "list_connections/2" do
    test "lists active connections for an RA instance", %{ra: ra} do
      {:ok, _c1} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-a"})
      {:ok, _c2} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-b"})

      connections = CaConnectionManagement.list_connections(nil, ra.id)
      assert length(connections) == 2
    end

    test "excludes revoked connections", %{ra: ra} do
      {:ok, c1} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-active"})
      {:ok, c2} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-revoked"})
      CaConnectionManagement.disconnect(nil, c2.id)

      connections = CaConnectionManagement.list_connections(nil, ra.id)
      assert length(connections) == 1
      assert hd(connections).id == c1.id
    end
  end

  describe "list_connected_issuer_keys/1" do
    test "returns issuer key IDs for active connections", %{ra: ra} do
      {:ok, _} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-x"})
      {:ok, c2} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-y"})
      CaConnectionManagement.disconnect(nil, c2.id)

      keys = CaConnectionManagement.list_connected_issuer_keys(nil)
      assert "key-x" in keys
      refute "key-y" in keys
    end
  end

  describe "has_connections?/1" do
    test "returns false when no active connections exist" do
      refute CaConnectionManagement.has_connections?(nil)
    end

    test "returns true when at least one active connection exists", %{ra: ra} do
      {:ok, _} = CaConnectionManagement.connect(nil, ra.id, %{issuer_key_id: "key-exists"})
      assert CaConnectionManagement.has_connections?(nil)
    end
  end
end
