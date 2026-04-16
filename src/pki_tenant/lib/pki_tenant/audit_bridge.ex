defmodule PkiTenant.AuditBridge do
  @moduledoc """
  Forwards audit events from tenant to platform via distributed Erlang.
  Fire-and-forget GenServer.cast. Buffers last 1000 events in a :queue
  and flushes when connection restores.

  Connection state is cached as :connected | :disconnected. Node.ping is
  only called during init and on the periodic 5-second reconnect timer, not
  on every audit event.
  """
  use GenServer
  require Logger

  @max_buffer 1000
  @reconnect_interval 5_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Log an audit event. Fire-and-forget."
  def log(action, attrs \\ %{}) do
    GenServer.cast(__MODULE__, {:log, action, attrs})
  end

  @impl true
  def init(opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    platform_node = Keyword.get(opts, :platform_node)

    platform_atom = if platform_node, do: String.to_atom(platform_node), else: nil

    connected =
      if platform_atom do
        case Node.ping(platform_atom) do
          :pong ->
            send_ready(platform_atom, tenant_id)
            true

          _ ->
            Logger.warning("[audit_bridge] Could not connect to platform node #{platform_atom} on init")
            false
        end
      else
        false
      end

    # Schedule periodic reconnect regardless — it's a no-op when already connected
    schedule_reconnect()

    {:ok,
     %{
       tenant_id: tenant_id,
       platform_node: platform_atom,
       connected: connected,
       buffer: :queue.new(),
       buffer_size: 0
     }}
  end

  @impl true
  def handle_cast({:log, action, attrs}, state) do
    event =
      Map.merge(attrs, %{
        action: action,
        tenant_id: state.tenant_id,
        timestamp: DateTime.utc_now()
      })

    case {state.platform_node, state.connected} do
      {nil, _} ->
        {:noreply, buffer_event(state, event)}

      {_node, false} ->
        {:noreply, buffer_event(state, event)}

      {node, true} ->
        GenServer.cast({PkiPlatformEngine.AuditReceiver, node}, {:audit_event, event})
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:reconnect, %{platform_node: nil} = state) do
    schedule_reconnect()
    {:noreply, state}
  end

  @impl true
  def handle_info(:reconnect, state) do
    case Node.ping(state.platform_node) do
      :pong ->
        if not state.connected do
          Logger.info("[audit_bridge] Reconnected to platform node #{state.platform_node}, flushing buffer")
        end

        state = flush_buffer(%{state | connected: true})
        schedule_reconnect()
        {:noreply, state}

      :pang ->
        if state.connected do
          Logger.warning("[audit_bridge] Lost connection to platform node #{state.platform_node}")
        end

        schedule_reconnect()
        {:noreply, %{state | connected: false}}
    end
  end

  defp schedule_reconnect do
    Process.send_after(self(), :reconnect, @reconnect_interval)
  end

  defp buffer_event(state, event) do
    {buffer, size} =
      if state.buffer_size >= @max_buffer do
        {_, q} = :queue.out(state.buffer)
        {q, state.buffer_size}
      else
        {state.buffer, state.buffer_size + 1}
      end

    %{state | buffer: :queue.in(event, buffer), buffer_size: size}
  end

  defp flush_buffer(%{buffer_size: 0} = state), do: state

  defp flush_buffer(state) do
    events = :queue.to_list(state.buffer)

    Enum.each(events, fn event ->
      GenServer.cast({PkiPlatformEngine.AuditReceiver, state.platform_node}, {:audit_event, event})
    end)

    %{state | buffer: :queue.new(), buffer_size: 0}
  end

  defp send_ready(platform_node, tenant_id) do
    GenServer.cast({PkiPlatformEngine.AuditReceiver, platform_node}, {:tenant_ready, tenant_id})
  rescue
    _ -> Logger.warning("[audit_bridge] Could not send :tenant_ready to platform")
  end
end
