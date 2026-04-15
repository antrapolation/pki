defmodule PkiCaEngine.Audit do
  @moduledoc """
  Audit logging for CA engine operations. Writes events to the tenant's
  audit_events table via the dynamic repo.

  In schema mode there is no global audit table, so nil tenant_id is a
  no-op (logged as a warning). For tenant-scoped calls, writes to the
  tenant's ca schema (hash chain per tenant is a future enhancement).
  """

  alias PkiCaEngine.TenantRepo
  alias PkiAuditTrail.AuditEvent

  @doc """
  Log an audit event for a tenant.

  ## Parameters
  - `tenant_id` — tenant context (nil for single-tenant)
  - `actor` — map with :actor_did, :actor_role
  - `action` — string (must be in PkiAuditTrail.Actions)
  - `resource` — map with :resource_type, :resource_id, optional :details, :ca_instance_id
  """
  def log(nil, _actor, action, resource) do
    require Logger

    Logger.warning(
      "[Audit] dropping event action=#{action} resource=#{inspect(resource[:resource_type])}/#{inspect(resource[:resource_id])} reason=no_tenant_context"
    )

    :ok
  end

  def log(tenant_id, actor, action, resource) do
    repo = TenantRepo.ca_repo(tenant_id)

    attrs = %{
      event_id: Ecto.UUID.generate(),
      timestamp: DateTime.utc_now(),
      node_name: to_string(node()),
      actor_did: actor[:actor_did] || actor[:id] || "system",
      actor_role: actor[:actor_role] || actor[:role] || "system",
      action: action,
      resource_type: resource[:resource_type],
      resource_id: resource[:resource_id],
      details: resource[:details] || %{},
      ca_instance_id: resource[:ca_instance_id],
      prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
      event_hash: :crypto.hash(:sha3_256, "#{action}:#{resource[:resource_id]}:#{DateTime.utc_now()}") |> Base.encode16(case: :lower)
    }

    case %AuditEvent{} |> AuditEvent.changeset(attrs) |> repo.insert() do
      {:ok, event} -> {:ok, event}
      {:error, _} = err -> err
    end
  rescue
    e ->
      require Logger
      Logger.warning("[Audit] Failed to log #{action}: #{Exception.message(e)}")
      :ok
  end
end
