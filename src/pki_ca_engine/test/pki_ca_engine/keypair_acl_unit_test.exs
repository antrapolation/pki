defmodule PkiCaEngine.KeypairAclUnitTest do
  # Pure-function tests for KeypairACL helpers. No DB, no Ecto sandbox.
  use ExUnit.Case, async: true

  alias PkiCaEngine.KeypairACL
  alias PkiCrypto.Symmetric

  describe "derive_wrap_key/3" do
    test "is deterministic for the same inputs" do
      root_key = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)

      a = KeypairACL.derive_wrap_key(root_key, salt, "signing")
      b = KeypairACL.derive_wrap_key(root_key, salt, "signing")

      assert a == b
      assert byte_size(a) == 32
    end

    test "signing and kem wrap keys differ from the root key and from each other" do
      root_key = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)

      signing = KeypairACL.derive_wrap_key(root_key, salt, "signing")
      kem = KeypairACL.derive_wrap_key(root_key, salt, "kem")

      # Domain separation: both wrap keys are distinct from each other.
      assert signing != kem
      # And neither wrap key equals the root key.
      assert signing != root_key
      assert kem != root_key
    end

    test "different salts produce different wrap keys for the same credential type" do
      root_key = :crypto.strong_rand_bytes(32)
      salt_a = :crypto.strong_rand_bytes(32)
      salt_b = :crypto.strong_rand_bytes(32)

      assert KeypairACL.derive_wrap_key(root_key, salt_a, "signing") !=
               KeypairACL.derive_wrap_key(root_key, salt_b, "signing")
    end

    test "raises for unknown credential types" do
      root_key = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)

      assert_raise FunctionClauseError, fn ->
        KeypairACL.derive_wrap_key(root_key, salt, "unknown-type")
      end
    end

    test "wrap key round-trips AES-GCM encryption" do
      root_key = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)
      wrap_key = KeypairACL.derive_wrap_key(root_key, salt, "signing")

      plaintext = "ACL signing private key bytes"
      {:ok, ciphertext} = Symmetric.encrypt(plaintext, wrap_key)
      assert {:ok, ^plaintext} = Symmetric.decrypt(ciphertext, wrap_key)

      # Key derived for the OTHER credential type cannot decrypt.
      kem_key = KeypairACL.derive_wrap_key(root_key, salt, "kem")
      assert {:error, :decryption_failed} = Symmetric.decrypt(ciphertext, kem_key)

      # Neither can the raw root key.
      assert {:error, :decryption_failed} = Symmetric.decrypt(ciphertext, root_key)
    end
  end

  describe "decrypt_acl_credential/3 — backward compat" do
    test "decrypts v1 (HKDF-wrapped) blob" do
      root_key = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)
      wrap_key = KeypairACL.derive_wrap_key(root_key, salt, "signing")
      plaintext = "v1-wrapped signing key"
      {:ok, ciphertext} = Symmetric.encrypt(plaintext, wrap_key)

      # Simulate a Credential record — only the fields decrypt_acl_credential reads.
      cred = %{id: "fake-id-v1", credential_type: "signing", encrypted_private_key: ciphertext}

      assert {:ok, ^plaintext} = KeypairACL.decrypt_acl_credential(cred, root_key, salt)
    end

    test "decrypts legacy (raw-root-key-wrapped) blob and logs a warning" do
      # Pre-v1 ACLs encrypted with the raw root key — no domain separation.
      # Verify the fallback path still works so an in-place upgrade doesn't
      # brick existing deployments.
      root_key = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)
      plaintext = "legacy-wrapped signing key"
      {:ok, legacy_ciphertext} = Symmetric.encrypt(plaintext, root_key)

      cred = %{id: "fake-id-legacy", credential_type: "signing", encrypted_private_key: legacy_ciphertext}

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, ^plaintext} = KeypairACL.decrypt_acl_credential(cred, root_key, salt)
        end)

      assert log =~ "legacy pre-v1 wrap scheme"
    end

    test "returns error for nil credential" do
      assert {:error, :credential_not_found} =
               KeypairACL.decrypt_acl_credential(nil, <<0::256>>, <<0::256>>)
    end

    test "returns decryption error when neither scheme works" do
      root_key = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)
      wrong_key = :crypto.strong_rand_bytes(32)
      {:ok, ciphertext} = Symmetric.encrypt("secret", wrong_key)

      cred = %{id: "fake-bad", credential_type: "signing", encrypted_private_key: ciphertext}

      assert {:error, :decryption_failed} =
               KeypairACL.decrypt_acl_credential(cred, root_key, salt)
    end
  end
end
