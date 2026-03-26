defmodule PkiCrypto.KdfTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.Kdf

  describe "derive_key/3" do
    test "returns {:ok, 32-byte binary}" do
      assert {:ok, key} = Kdf.derive_key("password", "salt")
      assert is_binary(key)
      assert byte_size(key) == 32
    end

    test "same inputs produce same output (deterministic)" do
      assert {:ok, key1} = Kdf.derive_key("password", "salt")
      assert {:ok, key2} = Kdf.derive_key("password", "salt")
      assert key1 == key2
    end

    test "different passwords produce different keys" do
      assert {:ok, key1} = Kdf.derive_key("password1", "salt")
      assert {:ok, key2} = Kdf.derive_key("password2", "salt")
      assert key1 != key2
    end

    test "different salts produce different keys" do
      assert {:ok, key1} = Kdf.derive_key("password", "salt1")
      assert {:ok, key2} = Kdf.derive_key("password", "salt2")
      assert key1 != key2
    end
  end

  describe "derive_session_key/1" do
    test "returns {:ok, 32-byte binary}" do
      assert {:ok, key} = Kdf.derive_session_key("my_password")
      assert is_binary(key)
      assert byte_size(key) == 32
    end

    test "is deterministic for same password" do
      assert {:ok, key1} = Kdf.derive_session_key("my_password")
      assert {:ok, key2} = Kdf.derive_session_key("my_password")
      assert key1 == key2
    end
  end
end
