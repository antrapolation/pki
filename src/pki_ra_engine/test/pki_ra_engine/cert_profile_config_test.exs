defmodule PkiRaEngine.CertProfileConfigTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.CertProfileConfig

  @valid_attrs %{
    name: "standard_tls",
    key_usage: "digitalSignature",
    ext_key_usage: "serverAuth",
    digest_algo: "sha256",
    subject_dn_policy: %{"required" => ["CN"], "optional" => ["O", "OU"]},
    issuer_policy: %{"issuer_dn" => "CN=Test CA"},
    validity_policy: %{"days" => 365},
    timestamping_policy: %{"enabled" => true},
    crl_policy: %{"distribution_points" => ["http://crl.example.com"]},
    ocsp_policy: %{"responder_url" => "http://ocsp.example.com"},
    ca_repository_url: "http://ca.example.com/repo",
    issuer_url: "http://ca.example.com/issuer",
    included_extensions: %{"aia" => true, "cdp" => true},
    renewal_policy: %{"auto_renew" => false, "days_before" => 30},
    notification_profile: %{"email" => true},
    cert_publish_policy: %{"ldap" => true}
  }

  defp create_profile!(attrs \\ %{}) do
    {:ok, profile} = CertProfileConfig.create_profile(nil,Map.merge(@valid_attrs, attrs))
    profile
  end

  describe "create_profile/1" do
    test "creates profile with all fields" do
      assert {:ok, profile} = CertProfileConfig.create_profile(nil,@valid_attrs)
      assert profile.name == "standard_tls"
      assert profile.key_usage == "digitalSignature"
      assert profile.subject_dn_policy == %{"required" => ["CN"], "optional" => ["O", "OU"]}
      assert profile.validity_policy == %{"days" => 365}
    end

    test "fails without name" do
      assert {:error, changeset} = CertProfileConfig.create_profile(nil,%{key_usage: "digitalSignature"})
      assert errors_on(changeset)[:name]
    end

    test "fails with duplicate name" do
      create_profile!()
      assert {:error, changeset} = CertProfileConfig.create_profile(nil,@valid_attrs)
      assert errors_on(changeset)[:name]
    end
  end

  describe "get_profile/1" do
    test "returns profile by id" do
      profile = create_profile!()
      assert {:ok, found} = CertProfileConfig.get_profile(nil,profile.id)
      assert found.id == profile.id
    end

    test "returns error for non-existent id" do
      assert {:error, :not_found} = CertProfileConfig.get_profile(nil,Uniq.UUID.uuid7())
    end
  end

  describe "list_profiles/0" do
    test "lists all profiles" do
      create_profile!(%{name: "profile_a"})
      create_profile!(%{name: "profile_b"})

      profiles = CertProfileConfig.list_profiles(nil)
      assert length(profiles) == 2
    end

    test "returns empty list when none exist" do
      assert CertProfileConfig.list_profiles(nil) == []
    end
  end

  describe "update_profile/2" do
    test "updates profile fields" do
      profile = create_profile!()
      assert {:ok, updated} = CertProfileConfig.update_profile(nil,profile.id, %{key_usage: "keyEncipherment"})
      assert updated.key_usage == "keyEncipherment"
    end

    test "updates jsonb fields" do
      profile = create_profile!()
      new_policy = %{"days" => 730}
      assert {:ok, updated} = CertProfileConfig.update_profile(nil,profile.id, %{validity_policy: new_policy})
      assert updated.validity_policy == new_policy
    end

    test "returns error for non-existent profile" do
      assert {:error, :not_found} = CertProfileConfig.update_profile(nil,Uniq.UUID.uuid7(), %{key_usage: "x"})
    end
  end

  describe "delete_profile/1" do
    test "hard-deletes the profile" do
      profile = create_profile!()
      assert {:ok, _deleted} = CertProfileConfig.delete_profile(nil,profile.id)
      assert {:error, :not_found} = CertProfileConfig.get_profile(nil,profile.id)
    end

    test "returns error for non-existent profile" do
      assert {:error, :not_found} = CertProfileConfig.delete_profile(nil,Uniq.UUID.uuid7())
    end
  end
end
