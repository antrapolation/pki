defmodule PkiCaEngine.HsmGateway do
  @moduledoc """
  Manages a single connected HSM agent per tenant.

  The remote Go agent connects via WebSocket (JSON messages matching
  `priv/proto/hsm_gateway.proto`).  This GenServer tracks the agent's
  registration, routes sign requests to it, and handles disconnects.

  ## State

      %{
        agent_id:         String.t() | nil,
        available_keys:   [String.t()],
        pending_requests: %{request_id => {from, timer_ref}},
        sign_listeners:   %{pid => true}
      }

  ## Client API

  - `sign_request/5` — send a sign request to the agent; blocks until
    response or timeout.
  - `agent_connected?/1` — true when an agent has registered.
  - `available_keys/1` — list of key labels the agent advertised.
  - `register_agent/3` — called when agent sends a RegisterRequest.
  - `submit_sign_response/3` / `submit_sign_error/3` — called when
    agent sends a SignResponse.
  - `agent_disconnected/1` — called on WebSocket close.
  """

  use GenServer
  require Logger

  @default_sign_timeout 5_000

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Send a sign request to the connected agent. Blocks until response or timeout."
  def sign_request(server \\ __MODULE__, key_label, tbs_data, algorithm, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_sign_timeout)
    # Give GenServer.call a little headroom over the internal timer
    GenServer.call(server, {:sign_request, key_label, tbs_data, algorithm, timeout}, timeout + 1_000)
  end

  @doc "Check if an agent is currently connected."
  def agent_connected?(server \\ __MODULE__) do
    GenServer.call(server, :agent_connected?)
  end

  @doc "Get the list of key labels available on the connected agent."
  def available_keys(server \\ __MODULE__) do
    GenServer.call(server, :available_keys)
  end

  @doc "Register an agent (called when agent connects via WebSocket)."
  def register_agent(server \\ __MODULE__, agent_id, key_labels) do
    GenServer.call(server, {:register_agent, agent_id, key_labels})
  end

  @doc "Submit a successful sign response from the agent."
  def submit_sign_response(server \\ __MODULE__, request_id, signature) do
    GenServer.cast(server, {:sign_response, request_id, signature, nil})
  end

  @doc "Submit a sign error from the agent."
  def submit_sign_error(server \\ __MODULE__, request_id, error) do
    GenServer.cast(server, {:sign_response, request_id, nil, error})
  end

  @doc "Notify the gateway that the agent disconnected."
  def agent_disconnected(server \\ __MODULE__) do
    GenServer.cast(server, :agent_disconnected)
  end

  # ---------------------------------------------------------------------------
  # Server Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    {:ok,
     %{
       agent_id: nil,
       available_keys: [],
       pending_requests: %{},
       sign_listeners: %{}
     }}
  end

  @impl true
  def handle_call({:sign_request, key_label, tbs_data, _algorithm, timeout}, from, state) do
    cond do
      state.agent_id == nil ->
        {:reply, {:error, :agent_not_connected}, state}

      key_label not in state.available_keys ->
        {:reply, {:error, :key_not_available}, state}

      true ->
        request_id = generate_request_id()
        timer_ref = Process.send_after(self(), {:sign_timeout, request_id}, timeout)

        new_pending = Map.put(state.pending_requests, request_id, {from, timer_ref})

        # Notify listeners (used by tests to simulate agent response)
        Enum.each(state.sign_listeners, fn {pid, _} ->
          send(pid, {:sign_request, request_id, key_label, tbs_data})
        end)

        {:noreply, %{state | pending_requests: new_pending}}
    end
  end

  @impl true
  def handle_call(:agent_connected?, _from, state) do
    {:reply, state.agent_id != nil, state}
  end

  @impl true
  def handle_call(:available_keys, _from, state) do
    {:reply, state.available_keys, state}
  end

  @impl true
  def handle_call({:register_agent, agent_id, key_labels}, {from_pid, _}, state) do
    Logger.info("HSM agent registered: #{agent_id} with keys: #{inspect(key_labels)}")

    new_state = %{
      state
      | agent_id: agent_id,
        available_keys: key_labels,
        sign_listeners: Map.put(state.sign_listeners, from_pid, true)
    }

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_cast({:sign_response, request_id, signature, error}, state) do
    case Map.pop(state.pending_requests, request_id) do
      {nil, _} ->
        Logger.warning("Received sign response for unknown request: #{request_id}")
        {:noreply, state}

      {{from, timer_ref}, new_pending} ->
        Process.cancel_timer(timer_ref)
        reply = if error, do: {:error, error}, else: {:ok, signature}
        GenServer.reply(from, reply)
        {:noreply, %{state | pending_requests: new_pending}}
    end
  end

  @impl true
  def handle_cast(:agent_disconnected, state) do
    Logger.info("HSM agent disconnected: #{state.agent_id}")

    # Fail all pending requests
    Enum.each(state.pending_requests, fn {_id, {from, timer_ref}} ->
      Process.cancel_timer(timer_ref)
      GenServer.reply(from, {:error, :agent_disconnected})
    end)

    {:noreply,
     %{state | agent_id: nil, available_keys: [], pending_requests: %{}, sign_listeners: %{}}}
  end

  @impl true
  def handle_info({:sign_timeout, request_id}, state) do
    case Map.pop(state.pending_requests, request_id) do
      {nil, _} ->
        {:noreply, state}

      {{from, _timer_ref}, new_pending} ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, %{state | pending_requests: new_pending}}
    end
  end

  # ---------------------------------------------------------------------------
  # Private
  # ---------------------------------------------------------------------------

  defp generate_request_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
end
