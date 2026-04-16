defmodule PkiTenant.AuditBridge do
  @moduledoc """
  Forwards audit events from tenant to platform via distributed Erlang.
  Fire-and-forget GenServer.cast. Buffers last 1000 events in a :queue
  and flushes when connection restores.
  """
  use GenServer
  require Logger

  @max_buffer 1000

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

    if platform_atom do
      Node.connect(platform_atom)
      send_ready(platform_atom, tenant_id)
    end

    {:ok,
     %{
       tenant_id: tenant_id,
       platform_node: platform_atom,
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

    case state.platform_node do
      nil ->
        {:noreply, buffer_event(state, event)}

      node ->
        if Node.ping(node) == :pong do
          state = flush_buffer(state)
          GenServer.cast({PkiPlatformEngine.AuditReceiver, node}, {:audit_event, event})
          {:noreply, state}
        else
          {:noreply, buffer_event(state, event)}
        end
    end
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
