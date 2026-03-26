defmodule PkiCaEngine.KeypairACLTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeypairACL
  alias PkiCaEngine.CredentialManager
  alias PkiCaEngine.Schema.CaInstance

  @admin_password "admin-secure-password-123"

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "acl-test-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    # Create an admin user with credentials (to get a KEM public key)
    {:ok, admin} =
      CredentialManager.create_user_with_credentials(
        ca.id,
        %{username: "acl-admin-#{System.unique_integer([:positive])}", display_name: "Admin", role: "ca_admin"},
        @admin_password
      )

    admin_kem_cred = CredentialManager.get_kem_credential(admin.id)

    %{ca: ca, admin: admin, admin_kem_cred: admin_kem_cred}
  end

  describe "initialized?/1" do
    test "returns false before initialization", %{ca: ca} do
      refute KeypairACL.initialized?(ca.id)
    end

    test "returns true after initialization", %{ca: ca, admin_kem_cred: kem_cred} do
      assert {:ok, _result} = KeypairACL.initialize(ca.id, kem_cred.public_key)
      assert KeypairACL.initialized?(ca.id)
    end
  end

  describe "initialize/3" do
    test "creates ACL signing and KEM credentials", %{ca: ca, admin_kem_cred: kem_cred} do
      assert {:ok, result} = KeypairACL.initialize(ca.id, kem_cred.public_key)

      assert %{
               acl_signing: signing,
               acl_kem: kem,
               encrypted_acl_password: enc_pw,
               kem_ciphertext: ct,
               acl_salt: salt
             } = result

      assert signing.credential_type == "signing"
      assert signing.algorithm == "ECC-P256"
      assert signing.status == "active"
      assert is_binary(signing.public_key)
      assert is_binary(signing.encrypted_private_key)

      assert kem.credential_type == "kem"
      assert kem.algorithm == "ECDH-P256"
      assert kem.status == "active"
      assert is_binary(kem.public_key)
      assert is_binary(kem.encrypted_private_key)

      assert is_binary(enc_pw)
      assert is_binary(ct)
      assert is_binary(salt)
    end

    test "credentials belong to the virtual system user", %{ca: ca, admin_kem_cred: kem_cred} do
      assert {:ok, result} = KeypairACL.initialize(ca.id, kem_cred.public_key)
      assert result.acl_signing.user_id == KeypairACL.acl_user_id()
      assert result.acl_kem.user_id == KeypairACL.acl_user_id()
    end
  end

  describe "get_public_keys/0" do
    test "returns error when not initialized" do
      assert {:error, :not_initialized} = KeypairACL.get_public_keys()
    end

    test "returns both public keys after initialization", %{ca: ca, admin_kem_cred: kem_cred} do
      {:ok, result} = KeypairACL.initialize(ca.id, kem_cred.public_key)

      assert {:ok, pub_keys} = KeypairACL.get_public_keys()
      assert pub_keys.signing_public_key == result.acl_signing.public_key
      assert pub_keys.kem_public_key == result.acl_kem.public_key
    end
  end

  describe "activate/5" do
    test "decrypts ACL private keys with correct admin KEM key", %{ca: ca, admin: admin, admin_kem_cred: kem_cred} do
      {:ok, result} = KeypairACL.initialize(ca.id, kem_cred.public_key)

      # Decrypt admin's KEM private key using their password
      {:ok, admin_kem_priv} =
        PkiCaEngine.CredentialManager.KeyOps.decrypt_private_key(
          kem_cred.encrypted_private_key,
          kem_cred.salt,
          @admin_password
        )

      assert {:ok, acl_keys} =
               KeypairACL.activate(
                 admin_kem_priv,
                 result.encrypted_acl_password,
                 result.kem_ciphertext,
                 result.acl_salt
               )

      assert is_binary(acl_keys.signing_key)
      assert is_binary(acl_keys.kem_key)
    end

    test "round-trip: initialize, activate, sign, verify", %{ca: ca, admin_kem_cred: kem_cred} do
      {:ok, result} = KeypairACL.initialize(ca.id, kem_cred.public_key)

      # Decrypt admin's KEM private key
      {:ok, admin_kem_priv} =
        PkiCaEngine.CredentialManager.KeyOps.decrypt_private_key(
          kem_cred.encrypted_private_key,
          kem_cred.salt,
          @admin_password
        )

      # Activate ACL
      {:ok, acl_keys} =
        KeypairACL.activate(
          admin_kem_priv,
          result.encrypted_acl_password,
          result.kem_ciphertext,
          result.acl_salt
        )

      # Sign some data with the ACL signing key
      data = "grant envelope payload"
      signing_algo = PkiCrypto.Registry.get("ECC-P256")
      {:ok, signature} = PkiCrypto.Algorithm.sign(signing_algo, acl_keys.signing_key, data)

      # Verify with the ACL's public signing key
      {:ok, pub_keys} = KeypairACL.get_public_keys()
      assert :ok = PkiCrypto.Algorithm.verify(signing_algo, pub_keys.signing_public_key, signature, data)
    end

    test "fails with wrong KEM private key", %{ca: ca, admin_kem_cred: kem_cred} do
      {:ok, result} = KeypairACL.initialize(ca.id, kem_cred.public_key)

      # Generate a completely different KEM keypair
      wrong_algo = PkiCrypto.Registry.get("ECDH-P256")
      {:ok, %{private_key: wrong_priv}} = PkiCrypto.Algorithm.generate_keypair(wrong_algo)

      assert {:error, _reason} =
               KeypairACL.activate(
                 wrong_priv,
                 result.encrypted_acl_password,
                 result.kem_ciphertext,
                 result.acl_salt
               )
    end
  end
end
