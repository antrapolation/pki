defmodule PkiPlatformEngine.SecretManager.EnvBackendTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.SecretManager.EnvBackend

  setup do
    prev = System.get_env("PKI_PLATFORM_MASTER_KEY")

    on_exit(fn ->
      if prev,
        do: System.put_env("PKI_PLATFORM_MASTER_KEY", prev),
        else: System.delete_env("PKI_PLATFORM_MASTER_KEY")
    end)

    :ok
  end

  test "returns :no_master_key when env var is unset" do
    System.delete_env("PKI_PLATFORM_MASTER_KEY")
    assert {:error, :no_master_key} = EnvBackend.master_key()
  end

  test "returns :no_master_key on empty string" do
    System.put_env("PKI_PLATFORM_MASTER_KEY", "")
    assert {:error, :no_master_key} = EnvBackend.master_key()
  end

  test "returns {:ok, 32 bytes} on a valid base64-encoded 32-byte key" do
    key = :crypto.strong_rand_bytes(32)
    encoded = Base.encode64(key, padding: false)
    System.put_env("PKI_PLATFORM_MASTER_KEY", encoded)

    assert {:ok, decoded} = EnvBackend.master_key()
    assert decoded == key
    assert byte_size(decoded) == 32
  end

  test "returns :invalid_key_length when decoded bytes aren't exactly 32" do
    short = Base.encode64(:crypto.strong_rand_bytes(16), padding: false)
    System.put_env("PKI_PLATFORM_MASTER_KEY", short)

    assert {:error, :invalid_key_length} = EnvBackend.master_key()
  end

  test "returns :invalid_base64 on malformed input" do
    System.put_env("PKI_PLATFORM_MASTER_KEY", "not-base64-!@#$")
    assert {:error, :invalid_base64} = EnvBackend.master_key()
  end
end
