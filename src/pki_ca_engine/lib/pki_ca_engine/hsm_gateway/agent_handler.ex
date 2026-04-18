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

  alias PkiCaEngine.HsmGateway

  # ---------------------------------------------------------------------------
  # Cowboy WebSocket callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(req, _opts) do
    {:cowboy_websocket, req, %{gateway: HsmGateway, registered: false}, %{idle_timeout: 60_000}}
  end

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

    :ok = HsmGateway.register_agent(state.gateway, agent_id, key_labels)

    reply =
      Jason.encode!(%{
        "type" => "register_response",
        "accepted" => true
      })

    {[{:text, reply}], %{state | registered: true}}
  end

  defp handle_message(%{"type" => "sign_response"} = msg, state) do
    request_id = msg["request_id"]

    if msg["error"] do
      HsmGateway.submit_sign_error(state.gateway, request_id, msg["error"])
    else
      signature = Base.decode64!(msg["signature"])
      HsmGateway.submit_sign_response(state.gateway, request_id, signature)
    end

    {:ok, state}
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
end
