defmodule PkiAuditTrail.WalBuffer do
  @moduledoc """
  Mnesia-backed write-ahead log buffer for audit events.
  Events are written here first, then flushed to Postgres asynchronously.
  Uses disc_only_copies for durability with write-heavy workload.
  """

  @table :audit_wal_buffer

  def init do
    case :mnesia.create_table(@table, [
           attributes: [:id, :attrs],
           disc_only_copies: [node()],
           type: :set
         ]) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, @table}} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end

  def write(attrs) do
    id = System.unique_integer([:positive, :monotonic])

    case :mnesia.transaction(fn ->
           :mnesia.write({@table, id, attrs})
         end) do
      {:atomic, :ok} -> {:ok, id}
      {:aborted, reason} -> {:error, reason}
    end
  end

  def pending do
    case :mnesia.transaction(fn ->
           :mnesia.foldl(fn record, acc -> [record | acc] end, [], @table)
         end) do
      {:atomic, records} -> Enum.sort_by(records, fn {_, id, _} -> id end)
      {:aborted, _reason} -> []
    end
  end

  def flush(id) do
    case :mnesia.transaction(fn ->
           :mnesia.delete({@table, id})
         end) do
      {:atomic, :ok} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end
end
