defmodule PkiAuditTrail.HashChainStore do
  @moduledoc """
  ETS-backed store of per-tenant prev_hash values for the audit hash chain.

  On first access for a tenant, queries the DB for the last event_hash in that
  tenant's audit schema. On miss (no events yet) returns the genesis value.
  Updates are in-memory only; the authoritative value is always the DB.
  """
  use GenServer
  require Logger

  @table :pki_audit_hash_chain
  @genesis String.duplicate("0", 64)

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Returns the current prev_hash for tenant_id, seeding from DB on first call."
  def get_or_seed(tenant_id) when is_binary(tenant_id) do
    case :ets.lookup(@table, tenant_id) do
      [{_, hash}] ->
        hash

      [] ->
        hash = load_prev_hash(tenant_id)
        :ets.insert(@table, {tenant_id, hash})
        hash
    end
  end

  @doc "Updates the cached hash after a successful insert."
  def update(tenant_id, hash) when is_binary(tenant_id) and is_binary(hash) do
    :ets.insert(@table, {tenant_id, hash})
    :ok
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    {:ok, %{}}
  end

  defp load_prev_hash(tenant_id) do
    import Ecto.Query
    prefix = audit_prefix(tenant_id)

    query =
      from e in PkiAuditTrail.AuditEvent,
        order_by: [desc: e.id],
        limit: 1,
        select: e.event_hash

    PkiAuditTrail.Repo.one(query, prefix: prefix) || @genesis
  rescue
    _ -> @genesis
  end

  # Inlined prefix so pki_audit_trail does not depend on pki_platform_engine.
  defp audit_prefix(tenant_id) do
    hex = String.replace(tenant_id, "-", "")
    "t_#{hex}_audit"
  end
end
