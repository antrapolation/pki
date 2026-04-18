defmodule PkiIntegration.HsmKeystoreTest do
  @moduledoc """
  Integration tests for the KeyStore.Dispatcher with all three adapter types.

  Tests:
  - Software: create issuer key with keystore_type :software, dev-activate,
    sign via Dispatcher → verify signature
  - Local HSM: create issuer key with keystore_type :local_hsm, verify
    Dispatcher routes to LocalHsmAdapter (returns error since no real HSM)
  - Remote HSM: create issuer key with keystore_type :remote_hsm, verify
    Dispatcher routes to RemoteHsmAdapter (returns :agent_not_connected)
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.{KeyActivation, KeyStore.Dispatcher}

  setup do
    dir = TestHelper.setup_mnesia()
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    # Start KeyActivation under the canonical module name so the Dispatcher's
    # SoftwareAdapter finds it without needing per-call opts.
    {ka_pid, started_here?} =
      case KeyActivation.start_link(name: KeyActivation, timeout_ms: 60_000) do
        {:ok, pid} -> {pid, true}
        {:error, {:already_started, pid}} -> {pid, false}
      end

    on_exit(fn ->
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      if started_here? and Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: KeyActivation}
  end

  describe "software keystore via Dispatcher" do
    test "create issuer key, dev-activate, sign, verify signature", %{ka: ka} do
      # Generate an ECC key pair
      ec_key = :public_key.generate_key({:namedCurve, :secp256r1})
      priv_der = :public_key.der_encode(:ECPrivateKey, ec_key)

      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-hsm-sw-1",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :software
        })

      {:ok, _} = Repo.insert(key)

      # Dev-activate the key (bypasses ceremony)
      assert {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key.id, priv_der)

      # Sign via Dispatcher — should route to SoftwareAdapter
      tbs_data = :crypto.strong_rand_bytes(64)
      assert {:ok, signature} = Dispatcher.sign(key.id, tbs_data)
      assert is_binary(signature)
      assert byte_size(signature) > 0

      # Verify the signature using the OTP native public key format.
      # ECPrivateKey record: {:ECPrivateKey, version, priv_bytes, params, pub_bytes, _}
      native_ec_key = :public_key.der_decode(:ECPrivateKey, priv_der)
      params = elem(native_ec_key, 3)
      pub_bytes = elem(native_ec_key, 4)
      ec_pub = {{:ECPoint, pub_bytes}, params}
      assert :public_key.verify(tbs_data, :sha256, signature, ec_pub)
    end

    test "returns :not_active when key not activated" do
      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-hsm-sw-2",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :software
        })

      {:ok, _} = Repo.insert(key)

      assert {:error, :not_active} = Dispatcher.sign(key.id, "tbs-data")
    end
  end

  describe "local HSM keystore via Dispatcher" do
    test "routes to LocalHsmAdapter (returns error since no real HSM)" do
      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-hsm-local-1",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :local_hsm,
          hsm_config: %{
            "library_path" => "/nonexistent/libsofthsm2.so",
            "slot_id" => 0,
            "pin" => "1234",
            "key_label" => "test-key"
          }
        })

      {:ok, _} = Repo.insert(key)

      # Dispatcher routes to LocalHsmAdapter — no real HSM, so expect an error
      result = Dispatcher.sign(key.id, "tbs-data")
      assert {:error, _reason} = result
    end
  end

  describe "remote HSM keystore via Dispatcher" do
    test "routes to RemoteHsmAdapter, returns :agent_not_connected" do
      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-hsm-remote-1",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :remote_hsm,
          hsm_config: %{"key_label" => "test-key"}
        })

      {:ok, _} = Repo.insert(key)

      # No agent connected — RemoteHsmAdapter should return :agent_not_connected
      assert {:error, :agent_not_connected} = Dispatcher.sign(key.id, "tbs-data")
    end
  end

  describe "Dispatcher error cases" do
    test "returns :issuer_key_not_found for missing key" do
      assert {:error, :issuer_key_not_found} = Dispatcher.sign("nonexistent-id", "data")
    end

    test "returns :unknown_keystore_type for unrecognised keystore type" do
      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-hsm-unk-1",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :cloud_hsm
        })

      {:ok, _} = Repo.insert(key)

      assert {:error, :unknown_keystore_type} = Dispatcher.sign(key.id, "data")
    end

    test "key_available? returns false for non-activated software key" do
      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-hsm-avail-1",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :software
        })

      {:ok, _} = Repo.insert(key)

      refute Dispatcher.key_available?(key.id)
    end
  end
end
