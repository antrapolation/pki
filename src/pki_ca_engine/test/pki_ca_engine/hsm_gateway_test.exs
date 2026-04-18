defmodule PkiCaEngine.HsmGatewayTest do
  use ExUnit.Case, async: false

  alias PkiCaEngine.HsmGateway

  describe "start_link/1" do
    test "starts with no agent" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_start)
      refute HsmGateway.agent_connected?(pid)
      assert HsmGateway.available_keys(pid) == []
      GenServer.stop(pid)
    end
  end

  describe "sign_request/5" do
    test "returns {:error, :agent_not_connected} when no agent" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_no_agent)

      assert {:error, :agent_not_connected} =
               HsmGateway.sign_request(pid, "some-key", "tbs", "ECC-P256")

      GenServer.stop(pid)
    end
  end

  describe "register_agent/3" do
    test "updates agent_id and available_keys" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_register)

      :ok = HsmGateway.register_agent(pid, "agent-01", ["key-a", "key-b"])
      assert HsmGateway.agent_connected?(pid)
      assert HsmGateway.available_keys(pid) == ["key-a", "key-b"]

      GenServer.stop(pid)
    end
  end

  describe "sign_request with mock agent" do
    test "returns signature when agent responds" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_sign)
      mock_signature = :crypto.strong_rand_bytes(64)

      # Register from this process so we become a sign_listener
      :ok = HsmGateway.register_agent(pid, "agent-01", ["test-key"])

      # Spawn a responder that listens for sign_request messages
      parent = self()

      responder =
        spawn(fn ->
          receive do
            {:sign_request, request_id, _key_label, _tbs_data} ->
              HsmGateway.submit_sign_response(pid, request_id, mock_signature)
              send(parent, :responded)
          after
            5_000 -> :timeout
          end
        end)

      # Also register the responder as a listener
      # (the register_agent already put self() as listener, so forward)
      # We need to relay sign_request messages to the responder
      relay =
        spawn(fn ->
          receive do
            {:sign_request, _, _, _} = msg ->
              send(responder, msg)
          after
            5_000 -> :ok
          end
        end)

      # Add relay as a listener by hacking state — instead, we just
      # use the fact that the registering process (self()) gets the
      # sign_request message.  We'll forward it ourselves.
      _relay_unused = relay

      # Actually, the sign_listener is self() (the test process).
      # We need to forward sign_request messages to the responder from here.
      # Let's do it differently: spawn a task that calls sign_request,
      # and handle the forwarding in the test process.

      task =
        Task.async(fn ->
          HsmGateway.sign_request(pid, "test-key", "tbs-data", "ECC-P256", timeout: 3_000)
        end)

      # The test process (self()) is a sign_listener and will get the
      # {:sign_request, ...} message.  Forward it to trigger the response.
      receive do
        {:sign_request, request_id, _key_label, _tbs_data} ->
          HsmGateway.submit_sign_response(pid, request_id, mock_signature)
      after
        3_000 -> flunk("did not receive sign_request message")
      end

      assert {:ok, ^mock_signature} = Task.await(task, 5_000)

      GenServer.stop(pid)
    end

    test "returns {:error, :key_not_available} for unknown key" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_key_na)
      :ok = HsmGateway.register_agent(pid, "agent-01", ["key-a"])

      assert {:error, :key_not_available} =
               HsmGateway.sign_request(pid, "nonexistent-key", "tbs", "ECC-P256")

      GenServer.stop(pid)
    end

    test "returns {:error, :timeout} when agent does not respond" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_timeout)
      :ok = HsmGateway.register_agent(pid, "agent-01", ["test-key"])

      assert {:error, :timeout} =
               HsmGateway.sign_request(pid, "test-key", "tbs", "ECC-P256", timeout: 200)

      GenServer.stop(pid)
    end
  end

  describe "agent_disconnected/1" do
    test "clears state and fails pending requests" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_disconnect)
      :ok = HsmGateway.register_agent(pid, "agent-01", ["test-key"])
      assert HsmGateway.agent_connected?(pid)

      # Start a sign request that will be pending
      task =
        Task.async(fn ->
          HsmGateway.sign_request(pid, "test-key", "tbs", "ECC-P256", timeout: 5_000)
        end)

      # Give the sign request a moment to register
      Process.sleep(50)

      # Disconnect agent
      HsmGateway.agent_disconnected(pid)

      assert {:error, :agent_disconnected} = Task.await(task, 3_000)
      refute HsmGateway.agent_connected?(pid)
      assert HsmGateway.available_keys(pid) == []

      GenServer.stop(pid)
    end
  end

  describe "submit_sign_error/3" do
    test "returns error to caller" do
      {:ok, pid} = HsmGateway.start_link(name: :test_gw_sign_err)
      :ok = HsmGateway.register_agent(pid, "agent-01", ["test-key"])

      task =
        Task.async(fn ->
          HsmGateway.sign_request(pid, "test-key", "tbs", "ECC-P256", timeout: 3_000)
        end)

      receive do
        {:sign_request, request_id, _key_label, _tbs_data} ->
          HsmGateway.submit_sign_error(pid, request_id, "hsm_error")
      after
        3_000 -> flunk("did not receive sign_request message")
      end

      assert {:error, "hsm_error"} = Task.await(task, 5_000)

      GenServer.stop(pid)
    end
  end
end
