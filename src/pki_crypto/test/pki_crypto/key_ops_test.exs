defmodule PkiCrypto.KeyOpsTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.KeyOps

  @password "test-password-123"

  describe "generate_credential_keypair/2" do
    test "generates ECC-P256 signing keypair" do
      assert {:ok, result} = KeyOps.generate_credential_keypair("ECC-P256", @password)
      assert is_binary(result.public_key)
      assert is_binary(result.encrypted_private_key)
      assert is_binary(result.salt)
    end

    test "generates ECDH-P256 KEM keypair" do
      assert {:ok, result} = KeyOps.generate_credential_keypair("ECDH-P256", @password)
      assert is_binary(result.public_key)
      assert is_binary(result.encrypted_private_key)
      assert is_binary(result.salt)
    end

    test "generates RSA-4096 keypair" do
      assert {:ok, result} = KeyOps.generate_credential_keypair("RSA-4096", @password)
      assert is_binary(result.public_key)
      assert is_binary(result.encrypted_private_key)
    end

    test "returns error for unknown algorithm" do
      assert {:error, {:unknown_algorithm, "UNKNOWN"}} =
               KeyOps.generate_credential_keypair("UNKNOWN", @password)
    end
  end

  describe "decrypt_private_key/3" do
    test "decrypts with correct password" do
      {:ok, %{encrypted_private_key: enc, salt: salt}} =
        KeyOps.generate_credential_keypair("ECC-P256", @password)

      assert {:ok, key} = KeyOps.decrypt_private_key(enc, salt, @password)
      assert is_binary(key)
    end

    test "fails with wrong password" do
      {:ok, %{encrypted_private_key: enc, salt: salt}} =
        KeyOps.generate_credential_keypair("ECC-P256", @password)

      assert {:error, _} = KeyOps.decrypt_private_key(enc, salt, "wrong-password")
    end
  end

  describe "verify_key_ownership/3" do
    test "returns true with correct password" do
      {:ok, %{encrypted_private_key: enc, salt: salt}} =
        KeyOps.generate_credential_keypair("ECC-P256", @password)

      assert KeyOps.verify_key_ownership(enc, salt, @password) == true
    end

    test "returns false with wrong password" do
      {:ok, %{encrypted_private_key: enc, salt: salt}} =
        KeyOps.generate_credential_keypair("ECC-P256", @password)

      assert KeyOps.verify_key_ownership(enc, salt, "wrong-password") == false
    end
  end

  describe "session key operations" do
    test "encrypt_for_session and decrypt_with_session_key round-trip" do
      {:ok, %{encrypted_private_key: enc, salt: salt}} =
        KeyOps.generate_credential_keypair("ECC-P256", @password)

      {:ok, private_key} = KeyOps.decrypt_private_key(enc, salt, @password)

      session_key = :crypto.strong_rand_bytes(32)
      {:ok, session_encrypted} = KeyOps.encrypt_for_session(private_key, session_key)
      {:ok, decrypted} = KeyOps.decrypt_with_session_key(session_encrypted, session_key)

      assert decrypted == private_key
    end
  end
end
