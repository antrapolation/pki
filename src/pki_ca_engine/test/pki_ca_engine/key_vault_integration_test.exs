defmodule PkiCaEngine.KeyVaultIntegrationTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeyVault
  alias PkiCaEngine.KeypairACL
  alias PkiCaEngine.CredentialManager
  alias PkiCaEngine.CredentialManager.Attestation
  alias PkiCaEngine.Schema.CaInstance
  alias PkiCrypto.{Algorithm, Registry, Symmetric}

  @admin_password "integration-test-password-123"

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "integ-test-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    # Create an admin user with credentials
    {:ok, admin} =
      CredentialManager.create_user_with_credentials(
        ca.id,
        %{username: "integ-admin-#{System.unique_integer([:positive])}", display_name: "Admin", role: "ca_admin"},
        @admin_password
      )

    admin_kem_cred = CredentialManager.get_kem_credential(admin.id)
    admin_signing_cred = CredentialManager.get_signing_credential(admin.id)

    # Initialize ACL with admin's KEM public key
    {:ok, acl_result} = KeypairACL.initialize(ca.id, admin_kem_cred.public_key)

    # Decrypt admin's KEM private key
    {:ok, admin_kem_priv} =
      CredentialManager.KeyOps.decrypt_private_key(
        admin_kem_cred.encrypted_private_key,
        admin_kem_cred.salt,
        @admin_password
      )

    # Decrypt admin's signing private key
    {:ok, admin_signing_priv} =
      CredentialManager.KeyOps.decrypt_private_key(
        admin_signing_cred.encrypted_private_key,
        admin_signing_cred.salt,
        @admin_password
      )

    # Activate ACL
    {:ok, acl_keys} =
      KeypairACL.activate(
        admin_kem_priv,
        acl_result.encrypted_acl_password,
        acl_result.kem_ciphertext,
        acl_result.acl_salt
      )

    {:ok, acl_pub_keys} = KeypairACL.get_public_keys()

    %{
      ca: ca,
      admin: admin,
      admin_kem_cred: admin_kem_cred,
      admin_kem_priv: admin_kem_priv,
      admin_signing_cred: admin_signing_cred,
      admin_signing_priv: admin_signing_priv,
      acl_result: acl_result,
      acl_keys: acl_keys,
      acl_pub_keys: acl_pub_keys
    }
  end

  # ── split_auth_token tests ──────────────────────────────────────────

  describe "register_keypair_split_auth/6" do
    test "returns keypair and N shares", %{ca: ca} do
      assert {:ok, keypair, shares} =
               KeyVault.register_keypair_split_auth(ca.id, "split-auth-1", "ECC-P256", 2, 3)

      assert keypair.protection_mode == "split_auth_token"
      assert keypair.threshold_k == 2
      assert keypair.threshold_n == 3
      assert length(shares) == 3
    end

    test "keypair has encrypted private key but no encrypted password", %{ca: ca} do
      {:ok, keypair, _shares} =
        KeyVault.register_keypair_split_auth(ca.id, "split-auth-2", "ECC-P256", 2, 3)

      assert is_binary(keypair.encrypted_private_key)
      assert keypair.encrypted_password == nil
    end

    test "public key is stored", %{ca: ca} do
      {:ok, keypair, _shares} =
        KeyVault.register_keypair_split_auth(ca.id, "split-auth-3", "ECC-P256", 2, 3)

      assert is_binary(keypair.public_key)
    end

    test "status defaults to pending", %{ca: ca} do
      {:ok, keypair, _shares} =
        KeyVault.register_keypair_split_auth(ca.id, "split-auth-4", "ECC-P256", 2, 3)

      assert keypair.status == "pending"
    end
  end

  # ── split_key tests ─────────────────────────────────────────────────

  describe "register_keypair_split_key/6" do
    test "returns keypair and N shares", %{ca: ca} do
      assert {:ok, keypair, shares} =
               KeyVault.register_keypair_split_key(ca.id, "split-key-1", "ECC-P256", 2, 3)

      assert keypair.protection_mode == "split_key"
      assert keypair.threshold_k == 2
      assert keypair.threshold_n == 3
      assert length(shares) == 3
    end

    test "no encrypted private key stored", %{ca: ca} do
      {:ok, keypair, _shares} =
        KeyVault.register_keypair_split_key(ca.id, "split-key-2", "ECC-P256", 2, 3)

      assert keypair.encrypted_private_key == nil
    end

    test "public key is stored", %{ca: ca} do
      {:ok, keypair, _shares} =
        KeyVault.register_keypair_split_key(ca.id, "split-key-3", "ECC-P256", 2, 3)

      assert is_binary(keypair.public_key)
    end

    test "status defaults to pending", %{ca: ca} do
      {:ok, keypair, _shares} =
        KeyVault.register_keypair_split_key(ca.id, "split-key-4", "ECC-P256", 2, 3)

      assert keypair.status == "pending"
    end
  end

  # ── activate_from_shares tests ──────────────────────────────────────

  describe "activate_from_shares/2 with split_auth_token" do
    test "recovers private key from K shares", %{ca: ca} do
      {:ok, keypair, shares} =
        KeyVault.register_keypair_split_auth(ca.id, "activate-auth-1", "ECC-P256", 2, 3)

      # Use only K=2 shares out of N=3
      k_shares = Enum.take(shares, 2)

      assert {:ok, private_key} = KeyVault.activate_from_shares(keypair.id, k_shares)
      assert is_binary(private_key)

      # Verify the recovered key can sign and verify
      algo = Registry.get("ECC-P256")
      data = "test data for split auth"
      {:ok, sig} = Algorithm.sign(algo, private_key, data)
      assert :ok = Algorithm.verify(algo, keypair.public_key, sig, data)
    end

    test "works with all N shares", %{ca: ca} do
      {:ok, keypair, shares} =
        KeyVault.register_keypair_split_auth(ca.id, "activate-auth-2", "ECC-P256", 2, 3)

      assert {:ok, private_key} = KeyVault.activate_from_shares(keypair.id, shares)

      algo = Registry.get("ECC-P256")
      {:ok, sig} = Algorithm.sign(algo, private_key, "verify all shares")
      assert :ok = Algorithm.verify(algo, keypair.public_key, sig, "verify all shares")
    end
  end

  describe "activate_from_shares/2 with split_key" do
    test "recovers private key from K shares", %{ca: ca} do
      {:ok, keypair, shares} =
        KeyVault.register_keypair_split_key(ca.id, "activate-key-1", "ECC-P256", 2, 3)

      k_shares = Enum.take(shares, 2)

      assert {:ok, private_key} = KeyVault.activate_from_shares(keypair.id, k_shares)
      assert is_binary(private_key)

      # Verify the recovered key can sign and verify
      algo = Registry.get("ECC-P256")
      data = "test data for split key"
      {:ok, sig} = Algorithm.sign(algo, private_key, data)
      assert :ok = Algorithm.verify(algo, keypair.public_key, sig, data)
    end

    test "works with all N shares", %{ca: ca} do
      {:ok, keypair, shares} =
        KeyVault.register_keypair_split_key(ca.id, "activate-key-2", "ECC-P256", 2, 3)

      assert {:ok, private_key} = KeyVault.activate_from_shares(keypair.id, shares)

      algo = Registry.get("ECC-P256")
      {:ok, sig} = Algorithm.sign(algo, private_key, "verify all shares key")
      assert :ok = Algorithm.verify(algo, keypair.public_key, sig, "verify all shares key")
    end
  end

  describe "activate_from_shares/2 edge cases" do
    test "returns error for non-existent keypair" do
      assert {:error, :not_found} = KeyVault.activate_from_shares(Uniq.UUID.uuid7(), [])
    end

    test "returns error for credential_own keypair", %{ca: ca, acl_pub_keys: pub_keys} do
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "cred-own-kp", "ECC-P256", pub_keys.kem_public_key)

      assert {:error, :invalid_protection_mode} =
               KeyVault.activate_from_shares(keypair.id, [<<"share1">>, <<"share2">>])
    end
  end

  # ── Attestation tests ──────────────────────────────────────────────

  describe "Attestation" do
    test "attest and verify round-trip", %{admin_signing_priv: priv, admin_signing_cred: cred} do
      # Generate a target keypair
      target_algo = Registry.get("ECC-P256")
      {:ok, %{public_key: target_pub}} = Algorithm.generate_keypair(target_algo)

      # Attest
      {:ok, signature} = Attestation.attest(priv, "ECC-P256", target_pub)
      assert is_binary(signature)

      # Verify
      assert :ok = Attestation.verify_attestation(cred.public_key, "ECC-P256", signature, target_pub)
    end

    test "verification fails with wrong admin key" do
      algo = Registry.get("ECC-P256")
      {:ok, %{public_key: _admin_pub, private_key: admin_priv}} = Algorithm.generate_keypair(algo)
      {:ok, %{public_key: target_pub}} = Algorithm.generate_keypair(algo)
      {:ok, %{public_key: other_pub}} = Algorithm.generate_keypair(algo)

      {:ok, signature} = Attestation.attest(admin_priv, "ECC-P256", target_pub)

      # Verify with wrong admin public key
      assert {:error, _} = Attestation.verify_attestation(other_pub, "ECC-P256", signature, target_pub)
    end

    test "verification fails with wrong target key" do
      algo = Registry.get("ECC-P256")
      {:ok, %{public_key: admin_pub, private_key: admin_priv}} = Algorithm.generate_keypair(algo)
      {:ok, %{public_key: target_pub}} = Algorithm.generate_keypair(algo)
      {:ok, %{public_key: other_target_pub}} = Algorithm.generate_keypair(algo)

      {:ok, signature} = Attestation.attest(admin_priv, "ECC-P256", target_pub)

      # Verify with wrong target public key
      assert {:error, _} = Attestation.verify_attestation(admin_pub, "ECC-P256", signature, other_target_pub)
    end
  end

  # ── Full integration flow tests ────────────────────────────────────

  describe "full credential_own integration flow" do
    test "end-to-end: create CA → user → ACL → register → grant → activate → sign → verify", ctx do
      %{
        ca: ca,
        acl_keys: acl_keys,
        acl_pub_keys: acl_pub_keys,
        admin_signing_cred: admin_signing_cred
      } = ctx

      # Step 4: Register a keypair with credential_own protection
      {:ok, keypair} =
        KeyVault.register_keypair(ca.id, "full-flow-keypair", "ECC-P256", acl_pub_keys.kem_public_key)

      # Step 5: Grant access to admin's signing credential
      {:ok, grant} =
        KeyVault.grant_access(keypair.id, admin_signing_cred.id, acl_keys.signing_key)

      assert KeyVault.has_grant?(keypair.id, admin_signing_cred.id)

      # Step 6: Activate ACL — already done in setup (acl_keys)
      # Step 7-8: Update status to active
      {:ok, active_keypair} = KeyVault.update_status(keypair.id, "active")
      assert active_keypair.status == "active"

      # Verify the keypair is stored correctly
      fetched = KeyVault.get_keypair(keypair.id)
      assert fetched.protection_mode == "credential_own"
      assert is_binary(fetched.encrypted_private_key)
      assert is_binary(fetched.encrypted_password)

      # Verify grant envelope signature is valid
      [envelope_json, sig_b64] = String.split(grant.signed_envelope, "||", parts: 2)
      signature = Base.decode64!(sig_b64)
      signing_algo = Registry.get("ECC-P256")
      assert :ok = Algorithm.verify(signing_algo, acl_pub_keys.signing_public_key, signature, envelope_json)
    end
  end

  describe "full split_auth_token integration flow" do
    test "register → get shares → recover from K shares → activate → sign → verify", %{ca: ca} do
      # Register keypair with split_auth_token (3-of-5)
      {:ok, keypair, shares} =
        KeyVault.register_keypair_split_auth(ca.id, "split-auth-flow", "ECC-P256", 3, 5)

      assert keypair.protection_mode == "split_auth_token"
      assert length(shares) == 5

      # Activate status
      {:ok, _} = KeyVault.update_status(keypair.id, "active")

      # Use only K=3 shares to recover
      k_shares = Enum.take(shares, 3)
      {:ok, private_key} = KeyVault.activate_from_shares(keypair.id, k_shares)

      # Sign data
      algo = Registry.get("ECC-P256")
      message = "split auth token integration test message"
      {:ok, signature} = Algorithm.sign(algo, private_key, message)

      # Verify with the stored public key
      assert :ok = Algorithm.verify(algo, keypair.public_key, signature, message)
    end
  end

  describe "full split_key integration flow" do
    test "register → get shares → recover from K shares → use private key → sign → verify", %{ca: ca} do
      # Register keypair with split_key (2-of-4)
      {:ok, keypair, shares} =
        KeyVault.register_keypair_split_key(ca.id, "split-key-flow", "ECC-P256", 2, 4)

      assert keypair.protection_mode == "split_key"
      assert keypair.encrypted_private_key == nil
      assert length(shares) == 4

      # Activate status
      {:ok, _} = KeyVault.update_status(keypair.id, "active")

      # Use only K=2 shares to recover
      k_shares = Enum.take(shares, 2)
      {:ok, private_key} = KeyVault.activate_from_shares(keypair.id, k_shares)

      # Sign data
      algo = Registry.get("ECC-P256")
      message = "split key integration test message"
      {:ok, signature} = Algorithm.sign(algo, private_key, message)

      # Verify with the stored public key
      assert :ok = Algorithm.verify(algo, keypair.public_key, signature, message)
    end
  end
end
