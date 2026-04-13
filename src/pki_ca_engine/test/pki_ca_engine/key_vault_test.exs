defmodule PkiCaEngine.KeyVaultTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeyVault
  alias PkiCaEngine.KeypairACL
  alias PkiCaEngine.CredentialManager
  alias PkiCaEngine.Schema.CaInstance

  @admin_password "vault-test-password-123"

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "vault-test-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    # Create an admin user with credentials
    {:ok, admin} =
      CredentialManager.create_user_with_credentials(
        nil,
        ca.id,
        %{username: "vault-admin-#{System.unique_integer([:positive])}", display_name: "Admin", role: "ca_admin"},
        @admin_password
      )

    admin_kem_cred = CredentialManager.get_kem_credential(nil, admin.id)

    # Initialize the ACL
    {:ok, acl_result} = KeypairACL.initialize(ca.id, admin_kem_cred.public_key)

    # Activate the ACL to get the signing and KEM keys
    {:ok, admin_kem_priv} =
      CredentialManager.KeyOps.decrypt_private_key(
        admin_kem_cred.encrypted_private_key,
        admin_kem_cred.salt,
        @admin_password
      )

    {:ok, acl_keys} =
      KeypairACL.activate(
        admin_kem_priv,
        acl_result.encrypted_acl_password,
        acl_result.kem_ciphertext,
        acl_result.acl_salt
      )

    {:ok, acl_pub_keys} = KeypairACL.get_public_keys()

    # Create a second user to test grants with different credentials
    {:ok, user2} =
      CredentialManager.create_user_with_credentials(
        nil,
        ca.id,
        %{username: "vault-user2-#{System.unique_integer([:positive])}", display_name: "User2", role: "key_manager"},
        "user2-password"
      )

    user2_signing_cred = CredentialManager.get_signing_credential(nil, user2.id)

    %{
      ca: ca,
      admin: admin,
      admin_kem_cred: admin_kem_cred,
      acl_result: acl_result,
      acl_keys: acl_keys,
      acl_pub_keys: acl_pub_keys,
      user2: user2,
      user2_signing_cred: user2_signing_cred
    }
  end

  describe "register_keypair/5" do
    test "creates a managed keypair with correct fields", %{ca: ca, acl_pub_keys: pub_keys} do
      assert {:ok, keypair} =
               KeyVault.register_keypair(ca.id, "test-keypair", "ECC-P256", pub_keys.kem_public_key)

      assert keypair.name == "test-keypair"
      assert keypair.algorithm == "ECC-P256"
      assert keypair.protection_mode == "credential_own"
      assert keypair.ca_instance_id == ca.id
      assert is_binary(keypair.public_key)
      assert is_binary(keypair.encrypted_private_key)
      assert is_binary(keypair.encrypted_password)
    end

    test "keypair status is 'pending' by default", %{ca: ca, acl_pub_keys: pub_keys} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "pending-keypair", "ECC-P256", pub_keys.kem_public_key)

      assert keypair.status == "pending"
    end
  end

  describe "grant_access/4" do
    test "creates a signed grant", %{ca: ca, acl_keys: acl_keys, acl_pub_keys: pub_keys, user2_signing_cred: cred} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "grant-keypair", "ECC-P256", pub_keys.kem_public_key)

      assert {:ok, grant} =
               KeyVault.grant_access(keypair.id, cred.id, acl_keys.signing_key)

      assert grant.managed_keypair_id == keypair.id
      assert grant.credential_id == cred.id
      assert is_binary(grant.signed_envelope)
      assert %DateTime{} = grant.granted_at
    end

    test "grant envelope contains keypair_id and credential_id", %{ca: ca, acl_keys: acl_keys, acl_pub_keys: pub_keys, user2_signing_cred: cred} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "envelope-keypair", "ECC-P256", pub_keys.kem_public_key)

      {:ok, grant} = KeyVault.grant_access(keypair.id, cred.id, acl_keys.signing_key)

      # The signed envelope is "json_data||base64_signature"
      [envelope_json, _signature] = String.split(grant.signed_envelope, "||", parts: 2)
      envelope = Jason.decode!(envelope_json)

      assert envelope["keypair_id"] == keypair.id
      assert envelope["credential_id"] == cred.id
    end
  end

  describe "has_grant?/2" do
    test "returns true after grant", %{ca: ca, acl_keys: acl_keys, acl_pub_keys: pub_keys, user2_signing_cred: cred} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "has-grant-keypair", "ECC-P256", pub_keys.kem_public_key)

      {:ok, _grant} = KeyVault.grant_access(keypair.id, cred.id, acl_keys.signing_key)

      assert KeyVault.has_grant?(keypair.id, cred.id)
    end

    test "returns false for non-granted credential", %{ca: ca, acl_pub_keys: pub_keys, user2_signing_cred: cred} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "no-grant-keypair", "ECC-P256", pub_keys.kem_public_key)

      refute KeyVault.has_grant?(keypair.id, cred.id)
    end
  end

  describe "revoke_grant/2" do
    test "sets revoked_at and has_grant? becomes false", %{ca: ca, acl_keys: acl_keys, acl_pub_keys: pub_keys, user2_signing_cred: cred} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "revoke-keypair", "ECC-P256", pub_keys.kem_public_key)

      {:ok, _grant} = KeyVault.grant_access(keypair.id, cred.id, acl_keys.signing_key)
      assert KeyVault.has_grant?(keypair.id, cred.id)

      assert {:ok, revoked_grant} = KeyVault.revoke_grant(keypair.id, cred.id)
      assert %DateTime{} = revoked_grant.revoked_at

      refute KeyVault.has_grant?(keypair.id, cred.id)
    end

    test "returns error for non-existent grant", %{ca: ca, acl_pub_keys: pub_keys, user2_signing_cred: cred} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "no-revoke-keypair", "ECC-P256", pub_keys.kem_public_key)

      assert {:error, :grant_not_found} = KeyVault.revoke_grant(keypair.id, cred.id)
    end
  end

  describe "list_keypairs/1" do
    test "returns keypairs for instance", %{ca: ca, acl_pub_keys: pub_keys} do
      {:ok, _kp1} = KeyVault.register_keypair(ca.id, "list-keypair-1", "ECC-P256", pub_keys.kem_public_key)
      {:ok, _kp2} = KeyVault.register_keypair(ca.id, "list-keypair-2", "ECC-P256", pub_keys.kem_public_key)

      keypairs = KeyVault.list_keypairs(ca.id)
      assert length(keypairs) == 2

      names = Enum.map(keypairs, & &1.name)
      assert "list-keypair-1" in names
      assert "list-keypair-2" in names
    end

    test "does not return keypairs from other instances", %{ca: ca, acl_pub_keys: pub_keys} do
      {:ok, _kp} = KeyVault.register_keypair(ca.id, "my-keypair", "ECC-P256", pub_keys.kem_public_key)

      other_id = Uniq.UUID.uuid7()
      assert KeyVault.list_keypairs(other_id) == []
    end
  end

  describe "update_status/2" do
    test "changes status", %{ca: ca, acl_pub_keys: pub_keys} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "status-keypair", "ECC-P256", pub_keys.kem_public_key)

      assert keypair.status == "pending"

      assert {:ok, updated} = KeyVault.update_status(keypair.id, "active")
      assert updated.status == "active"
    end

    test "returns error for non-existent keypair" do
      assert {:error, :not_found} = KeyVault.update_status(Uniq.UUID.uuid7(), "active")
    end
  end

  describe "get_keypair/1" do
    test "returns keypair by ID", %{ca: ca, acl_pub_keys: pub_keys} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "get-keypair", "ECC-P256", pub_keys.kem_public_key)

      result = KeyVault.get_keypair(keypair.id)
      assert result.id == keypair.id
      assert result.name == "get-keypair"
    end

    test "returns nil for non-existent ID" do
      assert KeyVault.get_keypair(Uniq.UUID.uuid7()) == nil
    end
  end
end
