defmodule PkiCaEngine.KeyStore.RemoteHsmAdapterTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.RemoteHsmAdapter
  alias PkiCaEngine.HsmGateway

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  test "sign returns :agent_not_connected when no gateway running" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    assert {:error, :agent_not_connected} = RemoteHsmAdapter.sign(key.id, "tbs-data")
  end

  test "key_available? returns false when no gateway running" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    refute RemoteHsmAdapter.key_available?(key.id)
  end

  test "sign delegates to HsmGateway, verifies against stored pubkey, returns signature" do
    # Post-PR #4: RemoteHsmAdapter verifies every signature the agent returns
    # against the issuer key's stored public key. The test must use a real
    # keypair + self-signed cert so the signature actually verifies.
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_remote_hsm_gw)

    ec_key = :public_key.generate_key({:namedCurve, :secp256r1})
    cert = X509.Certificate.self_signed(ec_key, "/CN=test-remote-hsm", template: :root_ca, hash: :sha256)
    cert_der = X509.Certificate.to_der(cert)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"},
      certificate_der: cert_der
    })
    {:ok, _} = Repo.insert(key)

    tbs_data = "tbs-data"

    # Produce a real signature with the matching private key. PkiCrypto
    # wraps this through its Algorithm protocol — use the same path the
    # Dispatcher would, so test and prod agree on the signature format.
    priv_der = :public_key.der_encode(:ECPrivateKey, ec_key)
    algo = PkiCrypto.Registry.get("ECC-P256")
    {:ok, real_signature} = PkiCrypto.Algorithm.sign(algo, priv_der, tbs_data)

    :ok = HsmGateway.register_agent(gw_pid, "agent-01", ["test-key"])

    task =
      Task.async(fn ->
        RemoteHsmAdapter.sign(key.id, tbs_data, gateway: gw_pid, timeout: 3_000)
      end)

    receive do
      {:sign_request, request_id, _key_label, _tbs_data} ->
        HsmGateway.submit_sign_response(gw_pid, request_id, real_signature)
    after
      3_000 -> flunk("did not receive sign_request message")
    end

    assert {:ok, ^real_signature} = Task.await(task, 5_000)

    GenServer.stop(gw_pid)
  end

  test "sign rejects when agent returns bytes that don't verify" do
    # A rogue or compromised agent that returns attacker-crafted bytes
    # must be rejected. Regression test for PR #4.
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_remote_hsm_rogue)

    ec_key = :public_key.generate_key({:namedCurve, :secp256r1})
    cert = X509.Certificate.self_signed(ec_key, "/CN=test-rogue-agent", template: :root_ca, hash: :sha256)
    cert_der = X509.Certificate.to_der(cert)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "rogue-key"},
      certificate_der: cert_der
    })
    {:ok, _} = Repo.insert(key)

    :ok = HsmGateway.register_agent(gw_pid, "agent-rogue", ["rogue-key"])

    task =
      Task.async(fn ->
        RemoteHsmAdapter.sign(key.id, "tbs-data", gateway: gw_pid, timeout: 3_000)
      end)

    # Return 64 random bytes — not a valid ECDSA signature over the TBS.
    bogus = :crypto.strong_rand_bytes(64)

    receive do
      {:sign_request, request_id, _, _} ->
        HsmGateway.submit_sign_response(gw_pid, request_id, bogus)
    after
      3_000 -> flunk("did not receive sign_request message")
    end

    assert {:error, :invalid_signature} = Task.await(task, 5_000)

    GenServer.stop(gw_pid)
  end

  test "sign returns :timeout when agent does not respond" do
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_remote_hsm_timeout)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    :ok = HsmGateway.register_agent(gw_pid, "agent-02", ["test-key"])

    result = RemoteHsmAdapter.sign(key.id, "tbs-data", gateway: gw_pid, timeout: 200)

    assert {:error, :timeout} = result

    GenServer.stop(gw_pid)
  end

  test "key_available? returns true when agent has the key" do
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_remote_hsm_avail)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    :ok = HsmGateway.register_agent(gw_pid, "agent-03", ["test-key"])

    assert RemoteHsmAdapter.key_available?(key.id, gateway: gw_pid)

    GenServer.stop(gw_pid)
  end

  test "key_available? returns false when agent lacks the key" do
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_remote_hsm_nokey)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "missing-key"}
    })
    {:ok, _} = Repo.insert(key)

    :ok = HsmGateway.register_agent(gw_pid, "agent-04", ["other-key"])

    refute RemoteHsmAdapter.key_available?(key.id, gateway: gw_pid)

    GenServer.stop(gw_pid)
  end
end
