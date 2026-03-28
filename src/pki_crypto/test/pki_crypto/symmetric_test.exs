defmodule PkiCrypto.SymmetricTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.Symmetric

  describe "encrypt/2 and decrypt/2" do
    test "round-trip with 32-byte key" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = "Hello, Post-Quantum World!"
      assert {:ok, ciphertext} = Symmetric.encrypt(plaintext, key)
      assert {:ok, ^plaintext} = Symmetric.decrypt(ciphertext, key)
    end

    test "decrypt with wrong key returns {:error, :decryption_failed}" do
      key = :crypto.strong_rand_bytes(32)
      wrong_key = :crypto.strong_rand_bytes(32)
      plaintext = "secret message"
      assert {:ok, ciphertext} = Symmetric.encrypt(plaintext, key)
      assert {:error, :decryption_failed} = Symmetric.decrypt(ciphertext, wrong_key)
    end

    test "different plaintexts produce different ciphertexts" do
      key = :crypto.strong_rand_bytes(32)
      assert {:ok, ct1} = Symmetric.encrypt("message one", key)
      assert {:ok, ct2} = Symmetric.encrypt("message two", key)
      assert ct1 != ct2
    end

    test "empty plaintext works" do
      key = :crypto.strong_rand_bytes(32)
      assert {:ok, ciphertext} = Symmetric.encrypt("", key)
      assert {:ok, ""} = Symmetric.decrypt(ciphertext, key)
    end

    test "large plaintext (100KB) works" do
      key = :crypto.strong_rand_bytes(32)
      plaintext = :crypto.strong_rand_bytes(100_000)
      assert {:ok, ciphertext} = Symmetric.encrypt(plaintext, key)
      assert {:ok, ^plaintext} = Symmetric.decrypt(ciphertext, key)
    end

    test "encrypt with wrong key size returns error" do
      assert {:error, :invalid_key_size} = Symmetric.encrypt("hello", "short_key")
      assert {:error, :invalid_key_size} = Symmetric.encrypt("hello", :crypto.strong_rand_bytes(16))
      assert {:error, :invalid_key_size} = Symmetric.encrypt("hello", :crypto.strong_rand_bytes(24))
    end

    test "decrypt with tampered GCM tag fails" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, <<iv::binary-12, tag::binary-16, body::binary>>} = Symmetric.encrypt("data", key)
      tampered_tag = :crypto.exor(tag, :crypto.strong_rand_bytes(16))
      assert {:error, :decryption_failed} = Symmetric.decrypt(iv <> tampered_tag <> body, key)
    end

    test "decrypt with truncated ciphertext fails" do
      key = :crypto.strong_rand_bytes(32)
      assert {:error, :decryption_failed} = Symmetric.decrypt(<<1, 2, 3>>, key)
    end
  end
end
