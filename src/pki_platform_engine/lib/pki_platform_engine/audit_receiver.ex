defmodule PkiPlatformEngine.AuditReceiver do
  @moduledoc """
  Receives audit event casts from tenant AuditBridge GenServers.
  Batch-writes to PostgreSQL every 100ms or 50 events.
  """
  use GenServer
  require Logger

  @flush_interval_ms 100
  @flush_batch_size 50

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(_opts) do
    schedule_flush()
    {:ok, %{buffer: [], count: 0}}
  end

  @impl true
  def handle_cast({:audit_event, event}, state) do
    new_buffer = [event | state.buffer]
    new_count = state.count + 1

    if new_count >= @flush_batch_size do
      flush(new_buffer)
      {:noreply, %{state | buffer: [], count: 0}}
    else
      {:noreply, %{state | buffer: new_buffer, count: new_count}}
    end
  end

  @impl true
  def handle_cast({:tenant_ready, tenant_id}, state) do
    Logger.info("[audit_receiver] Tenant #{tenant_id} reported ready")
    {:noreply, state}
  end

  @impl true
  def handle_info(:flush, state) do
    if state.count > 0 do
      flush(state.buffer)
    end

    schedule_flush()
    {:noreply, %{state | buffer: [], count: 0}}
  end

  defp flush(events) do
    Enum.each(events, fn event ->
      PkiPlatformEngine.PlatformAudit.log(
        event.action,
        Map.drop(event, [:action])
      )
    end)
  rescue
    e -> Logger.error("[audit_receiver] Flush failed: #{Exception.message(e)}")
  end

  defp schedule_flush do
    Process.send_after(self(), :flush, @flush_interval_ms)
  end
end
