defmodule PkiCaEngine.CredentialManager.KeyOpsTest do
  use ExUnit.Case, async: true

  alias PkiCaEngine.CredentialManager.KeyOps
  alias PkiCrypto.{Algorithm, Registry}

  @password "correct-horse-battery-staple"
  @wrong_password "wrong-password"

  describe "generate_credential_keypair/2" do
    test "returns public_key, encrypted_private_key, and salt for ECC-P256" do
      assert {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      assert Map.has_key?(result, :public_key)
      assert Map.has_key?(result, :encrypted_private_key)
      assert Map.has_key?(result, :salt)
    end

    test "public_key is a non-empty binary" do
      {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      assert is_binary(result.public_key)
      assert byte_size(result.public_key) > 0
    end

    test "encrypted_private_key is a non-empty binary different from raw private key" do
      {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      assert is_binary(result.encrypted_private_key)
      assert byte_size(result.encrypted_private_key) > 0

      # Decrypt to get raw key and confirm encrypted != raw
      {:ok, raw_priv} = KeyOps.decrypt_private_key(result.encrypted_private_key, result.salt, @password)
      assert result.encrypted_private_key != raw_priv
    end

    test "salt is 32 bytes" do
      {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      assert byte_size(result.salt) == 32
    end

    test "works for KEM algorithms (ECDH-P256)" do
      assert {:ok, result} = KeyOps.generate_credential_keypair("ECDH-P256", @password)
      assert is_binary(result.public_key)
      assert byte_size(result.public_key) > 0
    end

    test "returns error for unknown algorithm" do
      assert {:error, {:unknown_algorithm, "unknown"}} =
               KeyOps.generate_credential_keypair("unknown", @password)
    end
  end

  describe "decrypt_private_key/3" do
    test "correct password decrypts to original private key" do
      # Generate a keypair directly to get the raw private key for comparison
      algo = Registry.get("ECC-P256")
      {:ok, %{private_key: raw_priv}} = Algorithm.generate_keypair(algo)

      salt = PkiCrypto.Kdf.generate_salt()
      {:ok, derived_key} = PkiCrypto.Kdf.derive_key(@password, salt)
      {:ok, encrypted} = PkiCrypto.Symmetric.encrypt(raw_priv, derived_key)

      assert {:ok, decrypted} = KeyOps.decrypt_private_key(encrypted, salt, @password)
      assert decrypted == raw_priv
    end

    test "wrong password returns error" do
      {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)

      assert {:error, :decryption_failed} =
               KeyOps.decrypt_private_key(result.encrypted_private_key, result.salt, @wrong_password)
    end
  end

  describe "verify_key_ownership/3" do
    test "correct password returns true" do
      {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      assert KeyOps.verify_key_ownership(result.encrypted_private_key, result.salt, @password) == true
    end

    test "wrong password returns false" do
      {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      assert KeyOps.verify_key_ownership(result.encrypted_private_key, result.salt, @wrong_password) == false
    end
  end

  describe "round-trip: generate → decrypt → sign → verify" do
    test "decrypted key can sign and verify data" do
      {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      {:ok, priv_key} = KeyOps.decrypt_private_key(result.encrypted_private_key, result.salt, @password)

      algo = Registry.get("ECC-P256")
      data = "test message to sign"

      {:ok, signature} = Algorithm.sign(algo, priv_key, data)
      assert :ok = Algorithm.verify(algo, result.public_key, signature, data)
    end
  end

  describe "session key encrypt/decrypt" do
    test "round-trip with encrypt_for_session and decrypt_with_session_key" do
      session_key = :crypto.strong_rand_bytes(32)
      plaintext = :crypto.strong_rand_bytes(64)

      {:ok, encrypted} = KeyOps.encrypt_for_session(plaintext, session_key)
      assert encrypted != plaintext

      {:ok, decrypted} = KeyOps.decrypt_with_session_key(encrypted, session_key)
      assert decrypted == plaintext
    end
  end
end
