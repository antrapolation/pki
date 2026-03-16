defmodule PkiAuditTrail.Application do
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    ensure_mnesia_schema()
    PkiAuditTrail.WalBuffer.init()

    children = [
      PkiAuditTrail.Repo,
      PkiAuditTrail.Logger
    ]

    opts = [strategy: :one_for_one, name: PkiAuditTrail.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, pid} ->
        replay_wal()
        {:ok, pid}

      error ->
        error
    end
  end

  defp ensure_mnesia_schema do
    # Stop mnesia (started by extra_applications), create disc schema, restart
    :mnesia.stop()

    case :mnesia.create_schema([node()]) do
      :ok -> :ok
      {:error, {_, {:already_exists, _}}} -> :ok
      {:error, reason} ->
        Logger.error("Failed to create Mnesia schema: #{inspect(reason)}")
        raise "Mnesia schema creation failed: #{inspect(reason)}"
    end

    :mnesia.start()
  end

  @doc false
  def replay_wal do
    import Ecto.Query

    pending = PkiAuditTrail.WalBuffer.pending()

    for {_table, wal_id, attrs} <- pending do
      case PkiAuditTrail.Repo.one(
             from e in PkiAuditTrail.AuditEvent,
               where: e.event_id == ^attrs.event_id,
               select: e.id
           ) do
        nil ->
          Logger.warning("Discarding unflushed audit event #{attrs.event_id} — chain has advanced")
          PkiAuditTrail.WalBuffer.flush(wal_id)

        _exists ->
          PkiAuditTrail.WalBuffer.flush(wal_id)
      end
    end
  end
end
