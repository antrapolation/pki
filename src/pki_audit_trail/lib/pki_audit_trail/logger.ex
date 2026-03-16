defmodule PkiAuditTrail.Logger do
  @moduledoc """
  Core audit logging. Appends hash-chained events to the audit_events table.
  Uses a GenServer to serialize writes and maintain the chain.
  """

  use GenServer

  alias PkiAuditTrail.{AuditEvent, Hasher, Repo}

  # --- Client API ---

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Log an audit event.

  - `actor` — map with :actor_did, :actor_role, :node_name
  - `action` — string action name (e.g., "certificate_issued")
  - `resource` — map with :resource_type, :resource_id, and optional :details
  """
  def log(actor, action, resource) do
    GenServer.call(__MODULE__, {:log, actor, action, resource})
  end

  @doc false
  def reset do
    GenServer.call(__MODULE__, :reset)
  end

  # --- Server Callbacks ---

  @impl true
  def init(_opts) do
    prev_hash = fetch_last_hash()
    {:ok, %{prev_hash: prev_hash}}
  end

  @impl true
  def handle_call({:log, actor, action, resource}, _from, state) do
    unless PkiAuditTrail.Actions.valid?(action) do
      {:reply, {:error, {:invalid_action, action}}, state}
    else
    event_id = Ecto.UUID.generate()
    timestamp = DateTime.utc_now()

    attrs = %{
      event_id: event_id,
      timestamp: timestamp,
      node_name: Map.get(actor, :node_name, to_string(node())),
      actor_did: actor.actor_did,
      actor_role: actor.actor_role,
      action: action,
      resource_type: resource.resource_type,
      resource_id: resource.resource_id,
      details: Map.get(resource, :details, %{}),
      prev_hash: state.prev_hash
    }

    event_hash = Hasher.compute_hash(attrs)
    full_attrs = Map.put(attrs, :event_hash, event_hash)

    # Write to WAL buffer first (survives Postgres outage)
    {:ok, wal_id} = PkiAuditTrail.WalBuffer.write(full_attrs)

    case %AuditEvent{}
         |> AuditEvent.changeset(full_attrs)
         |> Repo.insert() do
      {:ok, event} ->
        # Flush from WAL on successful Postgres write
        case PkiAuditTrail.WalBuffer.flush(wal_id) do
          :ok -> :ok
          {:error, reason} ->
            require Logger
            Logger.warning("WAL flush failed for event: #{inspect(reason)}")
        end

        {:reply, {:ok, event}, %{state | prev_hash: event_hash}}

      {:error, changeset} ->
        # WAL entry retained — will be retried on startup
        {:reply, {:error, changeset}, state}
    end
    end
  end

  @impl true
  def handle_call(:reset, _from, _state) do
    prev_hash = fetch_last_hash()
    {:reply, :ok, %{prev_hash: prev_hash}}
  end

  defp fetch_last_hash do
    import Ecto.Query

    case Repo.one(from e in AuditEvent, order_by: [desc: e.id], limit: 1, select: e.event_hash) do
      nil -> Hasher.genesis_hash()
      hash -> hash
    end
  end
end
