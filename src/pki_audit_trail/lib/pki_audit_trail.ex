defmodule PkiAuditTrail do
  @moduledoc """
  Tamper-evident, hash-chained audit logging for PKI services.

  ## Usage

      PkiAuditTrail.log(
        %{actor_did: "did:ssdid:admin1", actor_role: "ca_admin", node_name: "node1"},
        "certificate_issued",
        %{resource_type: "certificate", resource_id: "cert-001", details: %{"serial" => "ABC"}}
      )

      PkiAuditTrail.verify_chain()
      PkiAuditTrail.query(action: "certificate_issued", actor_did: "did:ssdid:admin1")
  """

  import Ecto.Query
  require Logger, as: Log
  alias PkiAuditTrail.{AuditEvent, Logger, Repo, Verifier}

  defdelegate log(actor, action, resource), to: Logger
  defdelegate verify_chain(), to: Verifier

  @doc """
  Write a hash-chained audit event to a tenant's per-tenant audit schema.
  Only applicable to schema-mode tenants (those with a `t_<hex>_audit` Postgres schema).

  Returns `{:ok, event}` on success. On any failure (missing table, DB error)
  returns `{:error, reason}` and logs a warning — never raises.
  """
  def log(tenant_id, actor, action, resource)
      when is_binary(tenant_id) and is_map(actor) and is_binary(action) and is_map(resource) do
    prefix = audit_prefix(tenant_id)
    prev_hash = PkiAuditTrail.HashChainStore.get_or_seed(tenant_id)

    event_id = Ecto.UUID.generate()
    timestamp = DateTime.utc_now()

    attrs = %{
      event_id: event_id,
      timestamp: timestamp,
      node_name: Map.get(actor, :node_name, to_string(node())),
      actor_did: Map.fetch!(actor, :actor_did),
      actor_role: Map.get(actor, :actor_role, "unknown"),
      action: action,
      resource_type: Map.get(resource, :resource_type, ""),
      resource_id: to_string(Map.get(resource, :resource_id, "")),
      details: Map.get(resource, :details, %{}),
      ca_instance_id: Map.get(resource, :ca_instance_id),
      prev_hash: prev_hash
    }

    event_hash = PkiAuditTrail.Hasher.compute_hash(attrs)
    full_attrs = Map.put(attrs, :event_hash, event_hash)
    changeset = AuditEvent.changeset(%AuditEvent{}, full_attrs)

    case Repo.insert(changeset, prefix: prefix) do
      {:ok, event} ->
        PkiAuditTrail.HashChainStore.update(tenant_id, event_hash)
        {:ok, event}

      {:error, reason} ->
        Log.warning("[audit_trail] per-tenant write failed tenant_id=#{tenant_id} reason=#{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Log.warning("[audit_trail] per-tenant write exception tenant_id=#{tenant_id} error=#{Exception.message(e)}")
      {:error, :exception}
  end

  defp audit_prefix(tenant_id) do
    hex = String.replace(tenant_id, "-", "")
    "t_#{hex}_audit"
  end

  def query(filters \\ []) do
    AuditEvent
    |> apply_filters(filters)
    |> order_by(asc: :id)
    |> Repo.all()
  end

  defp apply_filters(query, []), do: query
  defp apply_filters(query, [{:action, action} | rest]),
    do: query |> where([e], e.action == ^action) |> apply_filters(rest)
  defp apply_filters(query, [{:actor_did, did} | rest]),
    do: query |> where([e], e.actor_did == ^did) |> apply_filters(rest)
  defp apply_filters(query, [{:resource_type, type} | rest]),
    do: query |> where([e], e.resource_type == ^type) |> apply_filters(rest)
  defp apply_filters(query, [{:resource_id, id} | rest]),
    do: query |> where([e], e.resource_id == ^id) |> apply_filters(rest)
  defp apply_filters(query, [{:ca_instance_id, id} | rest]),
    do: query |> where([e], e.ca_instance_id == ^id) |> apply_filters(rest)
  defp apply_filters(query, [{:since, since} | rest]),
    do: query |> where([e], e.timestamp >= ^since) |> apply_filters(rest)
  defp apply_filters(query, [{:until, until} | rest]),
    do: query |> where([e], e.timestamp <= ^until) |> apply_filters(rest)
  defp apply_filters(query, [_ | rest]), do: apply_filters(query, rest)
end
