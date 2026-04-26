defmodule PkiCaEngine.HsmGateway.AgentHandler do
  @moduledoc """
  WebSocket handler for HSM agent connections.

  Agents connect to `ws://host:port/hsm/connect` and exchange JSON
  messages that mirror the contract in `priv/proto/hsm_gateway.proto`.

  ## Protocol (JSON over WebSocket)

  Agent -> Server:

      {"type": "register", "tenant_id": "t1", "agent_id": "a1",
       "available_key_labels": ["k1", "k2"]}

      {"type": "sign_response", "request_id": "abc", "signature": "<base64>"}
      {"type": "sign_response", "request_id": "abc", "error": "reason"}

      {"type": "heartbeat", "timestamp": 1713000000}

  Server -> Agent:

      {"type": "register_response", "accepted": true}

      {"type": "sign_request", "request_id": "abc", "key_label": "k1",
       "tbs_data": "<base64>", "algorithm": "ECC-P256"}

      {"type": "heartbeat_ack", "timestamp": 1713000000}

  This module implements `Plug.Conn`-based WebSocket upgrade using
  Cowboy's `:cowboy_websocket` behaviour, so no extra deps are needed.
  """

  @behaviour :cowboy_websocket

  require Logger

  alias PkiCaEngine.{HsmGateway, HsmAgentSetup}

  # ---------------------------------------------------------------------------
  # Cowboy WebSocket callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(req, _opts) do
    peer_cert = safe_peer_cert(req)

    state = %{
      gateway: HsmGateway,
      registered: false,
      agent_id: nil,
      peer_cert_fingerprint: peer_cert_fingerprint(peer_cert),
      peer: :cowboy_req.peer(req)
    }

    {:cowboy_websocket, req, state, %{idle_timeout: 60_000}}
  end

  defp safe_peer_cert(req) do
    try do
      :cowboy_req.cert(req)
    rescue
      _ -> :undefined
    catch
      _, _ -> :undefined
    end
  end

  defp peer_cert_fingerprint(:undefined), do: nil
  defp peer_cert_fingerprint(nil), do: nil

  defp peer_cert_fingerprint(der) when is_binary(der) do
    :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)
  end

  defp peer_cert_fingerprint(_), do: nil

  @impl true
  def websocket_init(state) do
    {:ok, state}
  end

  @impl true
  def websocket_handle({:text, data}, state) do
    case Jason.decode(data) do
      {:ok, msg} ->
        handle_message(msg, state)

      {:error, _} ->
        Logger.warning("AgentHandler: received invalid JSON")
        {:ok, state}
    end
  end

  def websocket_handle(_frame, state) do
    {:ok, state}
  end

  @impl true
  def websocket_info({:sign_request, request_id, key_label, tbs_data}, state) do
    msg =
      Jason.encode!(%{
        "type" => "sign_request",
        "request_id" => request_id,
        "key_label" => key_label,
        "tbs_data" => Base.encode64(tbs_data),
        "algorithm" => "ECC-P256"
      })

    {[{:text, msg}], state}
  end

  def websocket_info(_info, state) do
    {:ok, state}
  end

  @impl true
  def terminate(_reason, _req, state) do
    if state.registered do
      HsmGateway.agent_disconnected(state.gateway)
    end

    :ok
  end

  # ---------------------------------------------------------------------------
  # Message dispatch
  # ---------------------------------------------------------------------------

  defp handle_message(%{"type" => "register"} = msg, state) do
    agent_id = msg["agent_id"] || "unknown"
    key_labels = msg["available_key_labels"] || []
    auth_token = msg["auth_token"] || ""
    tenant_id = msg["tenant_id"] || ""

    case authenticate_agent(agent_id, tenant_id, auth_token, key_labels) do
      :ok ->
        :ok = HsmGateway.register_agent(state.gateway, agent_id, key_labels)

        Logger.info(
          "HSM agent registered: agent_id=#{agent_id} tenant=#{tenant_id} " <>
            "peer=#{inspect(state.peer)} peer_cert=#{state.peer_cert_fingerprint || "<none>"}"
        )

        broadcast_agent_connected(agent_id, tenant_id, key_labels)
        update_wizard_setup(agent_id, tenant_id, key_labels)

        reply =
          Jason.encode!(%{
            "type" => "register_response",
            "accepted" => true
          })

        {[{:text, reply}], %{state | registered: true, agent_id: agent_id}}

      {:error, reason} ->
        Logger.warning(
          "HSM agent auth rejected: agent_id=#{inspect(agent_id)} reason=#{reason} " <>
            "peer=#{inspect(state.peer)} peer_cert=#{state.peer_cert_fingerprint || "<none>"}"
        )

        reply =
          Jason.encode!(%{
            "type" => "register_response",
            "accepted" => false,
            "error" => "unauthorized"
          })

        {[{:text, reply}, :close], state}
    end
  end

  defp handle_message(%{"type" => "sign_response"} = msg, %{registered: false} = state) do
    Logger.warning("AgentHandler: sign_response received before register — dropping")
    {[:close], state}
  end

  defp handle_message(%{"type" => "sign_response"} = msg, state) do
    request_id = msg["request_id"]

    cond do
      msg["error"] ->
        HsmGateway.submit_sign_error(state.gateway, request_id, msg["error"])
        {:ok, state}

      is_binary(msg["signature"]) ->
        case Base.decode64(msg["signature"]) do
          {:ok, signature} ->
            HsmGateway.submit_sign_response(state.gateway, request_id, signature)
            {:ok, state}

          :error ->
            Logger.warning(
              "AgentHandler: sign_response signature is not valid base64 — agent=#{state.agent_id}"
            )

            HsmGateway.submit_sign_error(state.gateway, request_id, "invalid_signature_encoding")
            {:ok, state}
        end

      true ->
        HsmGateway.submit_sign_error(state.gateway, request_id, "missing signature and error")
        {:ok, state}
    end
  end

  defp handle_message(%{"type" => "heartbeat"} = msg, state) do
    ack =
      Jason.encode!(%{
        "type" => "heartbeat_ack",
        "timestamp" => msg["timestamp"]
      })

    {[{:text, ack}], state}
  end

  defp handle_message(msg, state) do
    Logger.warning("AgentHandler: unknown message type: #{inspect(msg["type"])}")
    {:ok, state}
  end

  # ---------------------------------------------------------------------------
  # Agent authentication
  # ---------------------------------------------------------------------------
  #
  # Authenticates the registering agent. Fail-closed:
  #   - If :hsm_agent_tokens is not configured, reject unless :hsm_agent_allow_any
  #     is explicitly set to true (dev-only).
  #   - Each token entry: %{agent_id, tenant_id, token, key_labels}.
  #     `key_labels` may be :any to allow any labels the agent advertises,
  #     or a list — in which case the agent's advertised labels must be a
  #     subset.
  #   - Constant-time comparison on the token to avoid timing oracles.
  # ---------------------------------------------------------------------------
  defp authenticate_agent(agent_id, tenant_id, auth_token, key_labels) do
    configured = Application.get_env(:pki_ca_engine, :hsm_agent_tokens, [])
    allow_any = Application.get_env(:pki_ca_engine, :hsm_agent_allow_any, false)

    cond do
      configured == [] and allow_any ->
        Logger.warning(
          "HSM agent allow_any mode: accepting agent_id=#{agent_id} without token check. " <>
            "DO NOT run this in production."
        )

        :ok

      configured == [] ->
        # Fall through to wizard-registered token path
        HsmAgentSetup.authenticate_wizard_agent(agent_id, tenant_id, auth_token)

      auth_token == "" ->
        {:error, :missing_token}

      true ->
        entry = Enum.find(configured, &agent_match?(&1, agent_id, tenant_id))

        cond do
          entry == nil ->
            # Try wizard-registered token before rejecting
            HsmAgentSetup.authenticate_wizard_agent(agent_id, tenant_id, auth_token)

          not constant_time_equal?(entry[:token] || entry["token"] || "", auth_token) ->
            {:error, :invalid_token}

          not labels_allowed?(entry, key_labels) ->
            {:error, :labels_not_allowed}

          true ->
            :ok
        end
    end
  end

  defp agent_match?(entry, agent_id, tenant_id) do
    (entry[:agent_id] || entry["agent_id"]) == agent_id and
      (entry[:tenant_id] || entry["tenant_id"]) == tenant_id
  end

  defp labels_allowed?(entry, advertised) do
    case entry[:key_labels] || entry["key_labels"] do
      :any -> true
      "any" -> true
      nil -> false
      allowed when is_list(allowed) -> Enum.all?(advertised, &(&1 in allowed))
      _ -> false
    end
  end

  defp constant_time_equal?(a, b) when is_binary(a) and is_binary(b) do
    byte_size(a) == byte_size(b) and :crypto.hash_equals(a, b)
  end

  defp constant_time_equal?(_, _), do: false

  # Broadcast to the tenant PubSub topic so HsmDevicesLive resume banner updates
  # without a page reload. Uses dynamic dispatch since pki_ca_engine does not
  # depend on Phoenix directly; the PubSub module is injected via app config.
  defp broadcast_agent_connected(agent_id, tenant_id, key_labels) do
    case Application.get_env(:pki_ca_engine, :pubsub_module) do
      nil ->
        :ok

      pubsub ->
        try do
          apply(Phoenix.PubSub, :broadcast, [
            pubsub,
            "hsm_gateway:#{tenant_id}",
            {:agent_connected, agent_id, key_labels}
          ])
        rescue
          e -> Logger.warning("AgentHandler: PubSub broadcast failed: #{inspect(e)}")
        end
    end
  end

  # Mark the wizard setup record as agent_connected.
  defp update_wizard_setup(agent_id, tenant_id, key_labels) do
    case HsmAgentSetup.find_setup_id(agent_id, tenant_id) do
      {:ok, setup_id} -> HsmAgentSetup.mark_agent_connected(setup_id, key_labels)
      {:error, :not_found} -> :ok
    end
  end
end
