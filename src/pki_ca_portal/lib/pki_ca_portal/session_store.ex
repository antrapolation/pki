defmodule PkiCaPortal.SessionStore do
  @moduledoc """
  ETS-backed server-side session registry.

  Owns an ETS table that maps session_id to session data.
  Runs periodic cleanup of expired sessions.
  Broadcasts session events via PubSub for admin UI.
  """

  use GenServer
  require Logger

  @table :pki_ca_session_store
  @sweep_interval_ms 5 * 60 * 1000
  @pubsub PkiCaPortal.PubSub
  @pubsub_topic "session_events"

  # --- Client API ---

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def create(attrs) do
    GenServer.call(__MODULE__, {:create, attrs})
  end

  def lookup(session_id) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, record}] -> {:ok, record}
      [] -> {:error, :not_found}
    end
  end

  def touch(session_id) do
    GenServer.call(__MODULE__, {:touch, session_id})
  end

  def update_ip(session_id, new_ip) do
    GenServer.call(__MODULE__, {:update_ip, session_id, new_ip})
  end

  def update_profile(session_id, attrs) do
    GenServer.call(__MODULE__, {:update_profile, session_id, attrs})
  end

  def delete(session_id) do
    GenServer.call(__MODULE__, {:delete, session_id})
  end

  def list_all do
    :ets.tab2list(@table) |> Enum.map(fn {_id, record} -> record end)
  end

  def list_by_user(user_id) do
    list_all() |> Enum.filter(&(&1.user_id == user_id))
  end

  def expired?(session_id, timeout_ms) do
    case lookup(session_id) do
      {:ok, session} ->
        elapsed = DateTime.diff(DateTime.utc_now(), session.last_active_at, :millisecond)
        elapsed > timeout_ms

      {:error, :not_found} ->
        true
    end
  end

  def sweep(timeout_ms) do
    GenServer.call(__MODULE__, {:sweep, timeout_ms})
  end

  def clear_all do
    GenServer.call(__MODULE__, :clear_all)
  end

  # --- GenServer Callbacks ---

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :protected, read_concurrency: true])
    schedule_sweep()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:create, attrs}, _from, state) do
    session_id = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    now = DateTime.utc_now()

    record = %{
      session_id: session_id,
      user_id: attrs.user_id,
      username: attrs.username,
      role: attrs.role,
      tenant_id: attrs.tenant_id,
      ip: attrs.ip,
      user_agent: attrs.user_agent,
      display_name: attrs[:display_name],
      email: attrs[:email],
      ca_instance_id: attrs[:ca_instance_id],
      created_at: now,
      last_active_at: now
    }

    :ets.insert(@table, {session_id, record})
    broadcast(:session_created, record)
    {:reply, {:ok, session_id}, state}
  end

  def handle_call({:touch, session_id}, _from, state) do
    result = case :ets.lookup(@table, session_id) do
      [{^session_id, record}] ->
        updated = %{record | last_active_at: DateTime.utc_now()}
        :ets.insert(@table, {session_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end

    {:reply, result, state}
  end

  def handle_call({:update_ip, session_id, new_ip}, _from, state) do
    result = case :ets.lookup(@table, session_id) do
      [{^session_id, record}] ->
        updated = %{record | ip: new_ip, last_active_at: DateTime.utc_now()}
        :ets.insert(@table, {session_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end

    {:reply, result, state}
  end

  def handle_call({:update_profile, session_id, attrs}, _from, state) do
    result = case :ets.lookup(@table, session_id) do
      [{^session_id, record}] ->
        updated = record
          |> Map.put(:display_name, attrs[:display_name] || attrs["display_name"] || record.display_name)
          |> Map.put(:email, attrs[:email] || attrs["email"] || record.email)
          |> Map.put(:last_active_at, DateTime.utc_now())
        :ets.insert(@table, {session_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end

    {:reply, result, state}
  end

  def handle_call({:delete, session_id}, _from, state) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, record}] ->
        :ets.delete(@table, session_id)
        broadcast(:session_deleted, record)

      [] ->
        :ok
    end

    {:reply, :ok, state}
  end

  def handle_call({:sweep, timeout_ms}, _from, state) do
    count = do_sweep(timeout_ms)
    {:reply, count, state}
  end

  def handle_call(:clear_all, _from, state) do
    :ets.delete_all_objects(@table)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:sweep, state) do
    timeout_ms = Application.get_env(:pki_ca_portal, :session_idle_timeout_ms, 30 * 60 * 1000)
    count = do_sweep(timeout_ms)
    if count > 0, do: Logger.info("[session_store] Swept #{count} expired sessions")
    schedule_sweep()
    {:noreply, state}
  end

  defp do_sweep(timeout_ms) do
    now = DateTime.utc_now()

    expired =
      :ets.tab2list(@table)
      |> Enum.filter(fn {_id, record} ->
        DateTime.diff(now, record.last_active_at, :millisecond) > timeout_ms
      end)

    Enum.each(expired, fn {session_id, record} ->
      :ets.delete(@table, session_id)
      broadcast(:session_expired, record)
    end)

    length(expired)
  end

  defp schedule_sweep do
    Process.send_after(self(), :sweep, @sweep_interval_ms)
  end

  defp broadcast(event, session) do
    Phoenix.PubSub.broadcast(@pubsub, @pubsub_topic, {event, session})
  rescue
    _ -> :ok
  end
end
