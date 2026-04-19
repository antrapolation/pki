defmodule PkiCaEngine.KeyStore.DispatcherTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.Dispatcher

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  describe "sign/2" do
    test "routes :software keystore_type to SoftwareAdapter" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software
      })
      {:ok, _} = Repo.insert(key)

      # Without an active key in KeyActivation, SoftwareAdapter returns :not_active
      assert {:error, :not_active} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "routes :local_hsm keystore_type to LocalHsmAdapter" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :local_hsm,
        hsm_config: %{
          "library_path" => "/usr/lib/softhsm/libsofthsm2.so",
          "slot_id" => 0,
          "pin" => "1234",
          "key_label" => "test-key"
        }
      })
      {:ok, _} = Repo.insert(key)

      # LocalHsmAdapter is not yet implemented
      assert {:error, _reason} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "routes :remote_hsm keystore_type to RemoteHsmAdapter" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :remote_hsm,
        hsm_config: %{"key_label" => "test-key"}
      })
      {:ok, _} = Repo.insert(key)

      # Without a connected agent, RemoteHsmAdapter returns :agent_not_connected
      assert {:error, :agent_not_connected} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "returns :unknown_keystore_type for invalid type" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :cloud_hsm
      })
      {:ok, _} = Repo.insert(key)

      assert {:error, :unknown_keystore_type} = Dispatcher.sign(key.id, "tbs-data")
    end

    test "returns :issuer_key_not_found for missing key" do
      assert {:error, :issuer_key_not_found} = Dispatcher.sign("nonexistent-id", "tbs-data")
    end
  end

  describe "key_available?/1" do
    test "delegates to SoftwareAdapter for :software keys" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software
      })
      {:ok, _} = Repo.insert(key)

      # No key activated, so not available
      refute Dispatcher.key_available?(key.id)
    end

    test "returns false for unknown issuer_key_id" do
      refute Dispatcher.key_available?("nonexistent-id")
    end

    test "returns true for :local_hsm keys" do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :local_hsm
      })
      {:ok, _} = Repo.insert(key)

      assert Dispatcher.key_available?(key.id)
    end
  end
end
