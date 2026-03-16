defmodule PkiRaPortal.RaEngineClientTest do
  use ExUnit.Case, async: true

  alias PkiRaPortal.RaEngineClient

  describe "list_users/0" do
    test "returns a list of user maps" do
      assert {:ok, users} = RaEngineClient.list_users()
      assert is_list(users)
      assert length(users) > 0

      user = hd(users)
      assert Map.has_key?(user, :id)
      assert Map.has_key?(user, :did)
      assert Map.has_key?(user, :role)
      assert Map.has_key?(user, :status)
    end
  end

  describe "create_user/1" do
    test "returns created user with merged attributes" do
      attrs = %{did: "did:ssdid:new", display_name: "New User", role: "ra_officer"}
      assert {:ok, user} = RaEngineClient.create_user(attrs)
      assert user.did == "did:ssdid:new"
      assert user.role == "ra_officer"
      assert user.status == "active"
      assert is_integer(user.id)
    end
  end

  describe "delete_user/1" do
    test "returns user with suspended status" do
      assert {:ok, user} = RaEngineClient.delete_user(1)
      assert user.id == 1
      assert user.status == "suspended"
    end
  end

  describe "list_csrs/1" do
    test "returns a list of CSR maps" do
      assert {:ok, csrs} = RaEngineClient.list_csrs()
      assert is_list(csrs)
      assert length(csrs) > 0

      csr = hd(csrs)
      assert Map.has_key?(csr, :id)
      assert Map.has_key?(csr, :subject)
      assert Map.has_key?(csr, :status)
      assert Map.has_key?(csr, :profile_name)
    end

    test "filters by status" do
      assert {:ok, csrs} = RaEngineClient.list_csrs(status: "pending")
      assert Enum.all?(csrs, &(&1.status == "pending"))
    end
  end

  describe "get_csr/1" do
    test "returns a CSR map for a given id" do
      assert {:ok, csr} = RaEngineClient.get_csr(1)
      assert csr.id == 1
      assert Map.has_key?(csr, :subject)
      assert Map.has_key?(csr, :status)
    end
  end

  describe "approve_csr/2" do
    test "returns approved CSR" do
      assert {:ok, csr} = RaEngineClient.approve_csr(1)
      assert csr.id == 1
      assert csr.status == "approved"
    end
  end

  describe "reject_csr/3" do
    test "returns rejected CSR with reason" do
      assert {:ok, csr} = RaEngineClient.reject_csr(1, "Invalid subject")
      assert csr.id == 1
      assert csr.status == "rejected"
      assert csr.rejection_reason == "Invalid subject"
    end
  end

  describe "list_cert_profiles/0" do
    test "returns a list of cert profile maps" do
      assert {:ok, profiles} = RaEngineClient.list_cert_profiles()
      assert is_list(profiles)
      assert length(profiles) > 0

      profile = hd(profiles)
      assert Map.has_key?(profile, :name)
      assert Map.has_key?(profile, :key_usage)
      assert Map.has_key?(profile, :ext_key_usage)
      assert Map.has_key?(profile, :digest_algo)
      assert Map.has_key?(profile, :validity_days)
    end
  end

  describe "create_cert_profile/1" do
    test "returns created cert profile" do
      attrs = %{name: "Code Signing", key_usage: "digitalSignature", digest_algo: "SHA-256"}
      assert {:ok, profile} = RaEngineClient.create_cert_profile(attrs)
      assert profile.name == "Code Signing"
      assert is_integer(profile.id)
    end
  end

  describe "update_cert_profile/2" do
    test "returns updated cert profile" do
      attrs = %{validity_days: 180}
      assert {:ok, profile} = RaEngineClient.update_cert_profile(1, attrs)
      assert profile.id == 1
      assert profile.validity_days == 180
    end
  end

  describe "delete_cert_profile/1" do
    test "returns deleted confirmation" do
      assert {:ok, result} = RaEngineClient.delete_cert_profile(1)
      assert result.id == 1
      assert result.deleted == true
    end
  end

  describe "list_service_configs/0" do
    test "returns a list of service config maps" do
      assert {:ok, configs} = RaEngineClient.list_service_configs()
      assert is_list(configs)
      assert length(configs) > 0

      config = hd(configs)
      assert Map.has_key?(config, :service_type)
      assert Map.has_key?(config, :port)
      assert Map.has_key?(config, :url)
      assert Map.has_key?(config, :status)
    end
  end

  describe "configure_service/1" do
    test "returns configured service" do
      attrs = %{service_type: "OCSP Responder", port: 9090, url: "http://ocsp.test.com"}
      assert {:ok, svc} = RaEngineClient.configure_service(attrs)
      assert svc.service_type == "OCSP Responder"
      assert svc.status == "active"
      assert is_integer(svc.id)
    end
  end

  describe "list_api_keys/1" do
    test "returns a list of API key maps" do
      assert {:ok, keys} = RaEngineClient.list_api_keys()
      assert is_list(keys)
      assert length(keys) > 0

      key = hd(keys)
      assert Map.has_key?(key, :id)
      assert Map.has_key?(key, :name)
      assert Map.has_key?(key, :status)
    end
  end

  describe "create_api_key/1" do
    test "returns created API key with raw key" do
      attrs = %{name: "Test Key"}
      assert {:ok, key} = RaEngineClient.create_api_key(attrs)
      assert key.name == "Test Key"
      assert key.status == "active"
      assert Map.has_key?(key, :raw_key)
      assert is_binary(key.raw_key)
    end
  end

  describe "revoke_api_key/1" do
    test "returns revoked API key" do
      assert {:ok, key} = RaEngineClient.revoke_api_key(1)
      assert key.id == 1
      assert key.status == "revoked"
    end
  end
end
