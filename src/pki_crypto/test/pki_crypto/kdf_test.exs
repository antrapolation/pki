defmodule PkiCrypto.KdfTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.Kdf

  describe "derive_key/3" do
    test "returns {:ok, 32-byte binary}" do
      salt = Kdf.generate_salt()
      assert {:ok, key} = Kdf.derive_key("password", salt, iterations: 1000)
      assert is_binary(key)
      assert byte_size(key) == 32
    end

    test "same inputs produce same output (deterministic)" do
      salt = Kdf.generate_salt()
      assert {:ok, key1} = Kdf.derive_key("password", salt, iterations: 1000)
      assert {:ok, key2} = Kdf.derive_key("password", salt, iterations: 1000)
      assert key1 == key2
    end

    test "different passwords produce different keys" do
      salt = Kdf.generate_salt()
      assert {:ok, key1} = Kdf.derive_key("password1", salt, iterations: 1000)
      assert {:ok, key2} = Kdf.derive_key("password2", salt, iterations: 1000)
      assert key1 != key2
    end

    test "different salts produce different keys" do
      assert {:ok, key1} = Kdf.derive_key("password", Kdf.generate_salt(), iterations: 1000)
      assert {:ok, key2} = Kdf.derive_key("password", Kdf.generate_salt(), iterations: 1000)
      assert key1 != key2
    end

    test "custom length" do
      salt = Kdf.generate_salt()
      assert {:ok, key} = Kdf.derive_key("password", salt, length: 64, iterations: 1000)
      assert byte_size(key) == 64
    end
  end

  describe "derive_session_key/2" do
    test "returns {:ok, 32-byte binary}" do
      salt = Kdf.generate_salt()
      assert {:ok, key} = Kdf.derive_session_key("my_password", salt)
      assert is_binary(key)
      assert byte_size(key) == 32
    end

    test "same password and salt produce same key" do
      salt = Kdf.generate_salt()
      assert {:ok, key1} = Kdf.derive_session_key("my_password", salt)
      assert {:ok, key2} = Kdf.derive_session_key("my_password", salt)
      assert key1 == key2
    end

    test "same password with different salt produces different key" do
      assert {:ok, key1} = Kdf.derive_session_key("my_password", Kdf.generate_salt())
      assert {:ok, key2} = Kdf.derive_session_key("my_password", Kdf.generate_salt())
      assert key1 != key2
    end
  end

  describe "generate_salt/0" do
    test "returns 32 random bytes" do
      salt = Kdf.generate_salt()
      assert is_binary(salt)
      assert byte_size(salt) == 32
    end

    test "generates unique salts" do
      salt1 = Kdf.generate_salt()
      salt2 = Kdf.generate_salt()
      assert salt1 != salt2
    end
  end

  describe "hkdf/3" do
    test "derives key from high-entropy input" do
      ikm = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)
      assert {:ok, key} = Kdf.hkdf(ikm, salt)
      assert is_binary(key)
      assert byte_size(key) == 32
    end

    test "same inputs produce same output" do
      ikm = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)
      assert {:ok, key1} = Kdf.hkdf(ikm, salt)
      assert {:ok, key2} = Kdf.hkdf(ikm, salt)
      assert key1 == key2
    end

    test "different inputs produce different output" do
      salt = :crypto.strong_rand_bytes(32)
      assert {:ok, key1} = Kdf.hkdf(:crypto.strong_rand_bytes(32), salt)
      assert {:ok, key2} = Kdf.hkdf(:crypto.strong_rand_bytes(32), salt)
      assert key1 != key2
    end

    test "supports custom length and info" do
      ikm = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(32)
      assert {:ok, key} = Kdf.hkdf(ikm, salt, length: 64, info: "test")
      assert byte_size(key) == 64
    end
  end
end
