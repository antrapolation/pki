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

  test "sign delegates to HsmGateway and returns signature" do
    {:ok, gw_pid} = HsmGateway.start_link(name: :test_remote_hsm_gw)

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :remote_hsm,
      hsm_config: %{"key_label" => "test-key"}
    })
    {:ok, _} = Repo.insert(key)

    mock_signature = :crypto.strong_rand_bytes(64)

    # Register agent from this process so we get sign_request messages
    :ok = HsmGateway.register_agent(gw_pid, "agent-01", ["test-key"])

    # Start sign in a task
    task =
      Task.async(fn ->
        RemoteHsmAdapter.sign(key.id, "tbs-data", gateway: gw_pid, timeout: 3_000)
      end)

    # This process is a sign_listener — forward the response
    receive do
      {:sign_request, request_id, _key_label, _tbs_data} ->
        HsmGateway.submit_sign_response(gw_pid, request_id, mock_signature)
    after
      3_000 -> flunk("did not receive sign_request message")
    end

    assert {:ok, ^mock_signature} = Task.await(task, 5_000)

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
