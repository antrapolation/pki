defmodule PkiAuditTrail.Application do
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    if Application.get_env(:pki_audit_trail, :start_application, true) do
      ensure_mnesia_schema()
      PkiAuditTrail.WalBuffer.init()
    end

    # PkiAuditTrail.Logger (global hash-chained singleton) is disabled —
    # in schema mode audit_events has no global home; it lives per-tenant
    # under audit_prefix. Tenant-scoped audit writing goes through
    # PkiCaEngine.Audit. Phase 2 wires per-tenant prefix + hash chain.
    children =
      if Application.get_env(:pki_audit_trail, :start_application, true) do
        [
          PkiAuditTrail.Repo
        ]
      else
        []
      end

    if Application.get_env(:pki_audit_trail, :start_application, true) do
      Supervisor.start_link(children, strategy: :one_for_one, name: PkiAuditTrail.Supervisor)
    else
      Supervisor.start_link([], strategy: :one_for_one)
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
