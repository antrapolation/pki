defmodule PkiCaPortal.CaEngineClientTest do
  use ExUnit.Case, async: true

  alias PkiCaPortal.CaEngineClient

  @ca_instance_id 1

  describe "list_users/1" do
    test "returns a list of user maps" do
      assert {:ok, users} = CaEngineClient.list_users(@ca_instance_id)
      assert is_list(users)
      assert length(users) > 0

      user = hd(users)
      assert Map.has_key?(user, :id)
      assert Map.has_key?(user, :username)
      assert Map.has_key?(user, :role)
      assert Map.has_key?(user, :status)
    end
  end

  describe "create_user/2" do
    test "returns created user with merged attributes" do
      attrs = %{username: "newuser", display_name: "New User", role: "auditor"}
      assert {:ok, user} = CaEngineClient.create_user(@ca_instance_id, attrs)
      assert user.username == "newuser"
      assert user.role == "auditor"
      assert user.status == "active"
      assert is_binary(user.id)
    end
  end

  describe "get_user/1" do
    test "returns a user map for a given id" do
      assert {:ok, user} = CaEngineClient.get_user("019577a0-0042-7000-8000-000000000042")
      assert user.id == "019577a0-0042-7000-8000-000000000042"
      assert Map.has_key?(user, :username)
      assert Map.has_key?(user, :role)
    end
  end

  describe "delete_user/1" do
    test "returns user with suspended status" do
      assert {:ok, user} = CaEngineClient.delete_user("019577a0-0001-7000-8000-000000000001")
      assert user.id == "019577a0-0001-7000-8000-000000000001"
      assert user.status == "suspended"
    end
  end

  describe "list_keystores/1" do
    test "returns a list of keystore maps" do
      assert {:ok, keystores} = CaEngineClient.list_keystores(@ca_instance_id)
      assert is_list(keystores)

      ks = hd(keystores)
      assert Map.has_key?(ks, :type)
      assert Map.has_key?(ks, :status)
      assert Map.has_key?(ks, :provider_name)
    end
  end

  describe "configure_keystore/2" do
    test "returns configured keystore with merged attributes" do
      attrs = %{type: "hsm", provider_name: "TestProvider"}
      assert {:ok, ks} = CaEngineClient.configure_keystore(@ca_instance_id, attrs)
      assert ks.type == "hsm"
      assert ks.status == "active"
    end
  end

  describe "list_issuer_keys/1" do
    test "returns a list of issuer key maps" do
      assert {:ok, keys} = CaEngineClient.list_issuer_keys(@ca_instance_id)
      assert is_list(keys)

      key = hd(keys)
      assert Map.has_key?(key, :key_alias)
      assert Map.has_key?(key, :algorithm)
      assert Map.has_key?(key, :status)
    end
  end

  describe "get_engine_status/1" do
    test "returns engine status map" do
      assert {:ok, status} = CaEngineClient.get_engine_status(@ca_instance_id)
      assert Map.has_key?(status, :status)
      assert Map.has_key?(status, :active_keys)
      assert Map.has_key?(status, :uptime_seconds)
    end
  end

  describe "initiate_ceremony/2" do
    test "returns initiated ceremony" do
      params = %{algorithm: "ML-DSA-65"}
      assert {:ok, ceremony} = CaEngineClient.initiate_ceremony(@ca_instance_id, params)
      assert ceremony.status == "initiated"
      assert is_binary(ceremony.id)
    end
  end

  describe "list_ceremonies/1" do
    test "returns a list of ceremony maps" do
      assert {:ok, ceremonies} = CaEngineClient.list_ceremonies(@ca_instance_id)
      assert is_list(ceremonies)

      c = hd(ceremonies)
      assert Map.has_key?(c, :ceremony_type)
      assert Map.has_key?(c, :status)
      assert Map.has_key?(c, :algorithm)
    end
  end

  describe "query_audit_log/1" do
    test "returns a list of audit events" do
      assert {:ok, events} = CaEngineClient.query_audit_log([])
      assert is_list(events)

      event = hd(events)
      assert Map.has_key?(event, :event_id)
      assert Map.has_key?(event, :action)
      assert Map.has_key?(event, :actor)
      assert Map.has_key?(event, :timestamp)
    end
  end
end
