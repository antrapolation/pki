defmodule PkiPlatformEngine.SofthsmPinCustodyTest do
  @moduledoc """
  Cryptographic round-trip + tamper coverage for the v1 envelope.

  Uses a stub `SecretManager` backend that returns a fixed 32-byte
  key so tests don't depend on the `PKI_PLATFORM_MASTER_KEY` env
  var. The real env-var backend is covered separately.
  """
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.SofthsmPinCustody

  defmodule StubBackend do
    @behaviour PkiPlatformEngine.SecretManager
    @impl true
    def master_key, do: {:ok, <<1::256>>}
  end

  defmodule MissingBackend do
    @behaviour PkiPlatformEngine.SecretManager
    @impl true
    def master_key, do: {:error, :no_master_key}
  end

  defmodule AltBackend do
    @behaviour PkiPlatformEngine.SecretManager
    @impl true
    def master_key, do: {:ok, <<2::256>>}
  end

  setup do
    prev = Application.get_env(:pki_platform_engine, :secret_manager)
    Application.put_env(:pki_platform_engine, :secret_manager, StubBackend)

    on_exit(fn ->
      if prev,
        do: Application.put_env(:pki_platform_engine, :secret_manager, prev),
        else: Application.delete_env(:pki_platform_engine, :secret_manager)
    end)

    :ok
  end

  @tenant_id "01ffffff-0000-7000-8000-000000000001"

  describe "wrap/3 + unwrap/2 round-trip" do
    test "successfully decrypts a freshly-wrapped envelope" do
      assert {:ok, env} = SofthsmPinCustody.wrap(@tenant_id, "user-pin-1234", "so-pin-12345678")

      assert env["version"] == "v1"
      assert is_binary(env["salt"])
      assert is_binary(env["iv"])
      assert is_binary(env["user_pin_ct"])
      assert is_binary(env["so_pin_ct"])
      assert is_binary(env["wrapped_at"])

      assert {:ok, %{user_pin: "user-pin-1234", so_pin: "so-pin-12345678"}} =
               SofthsmPinCustody.unwrap(@tenant_id, env)
    end

    test "wrap produces a fresh salt + iv every call" do
      {:ok, a} = SofthsmPinCustody.wrap(@tenant_id, "user", "so")
      {:ok, b} = SofthsmPinCustody.wrap(@tenant_id, "user", "so")

      refute a["salt"] == b["salt"]
      refute a["iv"] == b["iv"]
      refute a["user_pin_ct"] == b["user_pin_ct"]
    end
  end

  describe "security properties" do
    test "decrypting with a different tenant_id (AAD mismatch) fails" do
      {:ok, env} = SofthsmPinCustody.wrap(@tenant_id, "user", "so")

      other_id = "01ffffff-0000-7000-8000-000000000002"
      assert {:error, :decryption_failed} = SofthsmPinCustody.unwrap(other_id, env)
    end

    test "a tampered ciphertext fails the auth-tag check" do
      {:ok, env} = SofthsmPinCustody.wrap(@tenant_id, "user", "so")

      # Flip the last bit of the user_pin ciphertext — GCM tag check
      # must reject.
      tampered =
        Map.update!(env, "user_pin_ct", fn encoded ->
          bytes = Base.url_decode64!(encoded, padding: false)
          size = byte_size(bytes)
          <<head::binary-size(size - 1), last>> = bytes
          Base.url_encode64(<<head::binary, Bitwise.bxor(last, 1)>>, padding: false)
        end)

      assert {:error, :decryption_failed} = SofthsmPinCustody.unwrap(@tenant_id, tampered)
    end

    test "decrypting with a different master key fails" do
      {:ok, env} = SofthsmPinCustody.wrap(@tenant_id, "user", "so")

      Application.put_env(:pki_platform_engine, :secret_manager, AltBackend)
      assert {:error, :decryption_failed} = SofthsmPinCustody.unwrap(@tenant_id, env)
    end
  end

  describe "error paths" do
    test "wrap returns {:error, :no_master_key} when backend has nothing" do
      Application.put_env(:pki_platform_engine, :secret_manager, MissingBackend)
      assert {:error, :no_master_key} = SofthsmPinCustody.wrap(@tenant_id, "a", "b")
    end

    test "unwrap rejects an unsupported envelope version" do
      env = %{"version" => "v999"}
      assert {:error, {:unsupported_envelope_version, "v999"}} =
               SofthsmPinCustody.unwrap(@tenant_id, env)
    end

    test "unwrap rejects a malformed envelope" do
      assert {:error, :malformed_envelope} =
               SofthsmPinCustody.unwrap(@tenant_id, %{"foo" => "bar"})
    end

    test "unwrap rejects envelope with bad base64" do
      {:ok, env} = SofthsmPinCustody.wrap(@tenant_id, "user", "so")
      broken = Map.put(env, "salt", "!!not-base64!!")
      assert {:error, :malformed_envelope} = SofthsmPinCustody.unwrap(@tenant_id, broken)
    end
  end
end
