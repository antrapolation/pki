defmodule PkiPlatformEngine.PlatformAudit do
  @moduledoc """
  Audit logging for platform-level operations.
  Writes to platform_audit_events and, for schema-mode tenants, also writes
  a hash-chained event to the tenant's per-tenant audit schema.
  """

  import Ecto.Query
  require Logger
  alias PkiPlatformEngine.{PlatformRepo, PlatformAuditEvent, Tenant, TenantPrefix}

  @doc """
  Log an audit event.

  ## Examples

      PlatformAudit.log("user_created", %{
        actor_id: admin.id,
        actor_username: admin.username,
        target_type: "user_profile",
        target_id: new_user.id,
        tenant_id: tenant_id,
        portal: "ca",
        details: %{username: "newuser", role: "ca_admin"}
      })
  """
  def log(action, attrs \\ %{}) do
    result =
      %PlatformAuditEvent{}
      |> PlatformAuditEvent.changeset(
        Map.merge(attrs, %{
          action: action,
          timestamp: DateTime.utc_now()
        })
      )
      |> PlatformRepo.insert()

    case Map.get(attrs, :tenant_id) do
      nil -> :ok
      tenant_id -> maybe_write_tenant_audit(tenant_id, action, attrs)
    end

    result
  end

  defp maybe_write_tenant_audit(tenant_id, action, attrs) do
    case PlatformRepo.get(Tenant, tenant_id) do
      %Tenant{schema_mode: "schema"} ->
        prefix = TenantPrefix.audit_prefix(tenant_id)
        prev_hash = PkiAuditTrail.HashChainStore.get_or_seed(tenant_id)

        event_id = Ecto.UUID.generate()
        timestamp = DateTime.utc_now()

        event_attrs = %{
          event_id: event_id,
          timestamp: timestamp,
          node_name: to_string(node()),
          actor_did: Map.get(attrs, :actor_username, "system"),
          actor_role: Map.get(attrs, :actor_role, "unknown"),
          action: action,
          resource_type: Map.get(attrs, :target_type, infer_resource_type(action)),
          resource_id: to_string(Map.get(attrs, :target_id, "")),
          details: Map.get(attrs, :details, %{}),
          ca_instance_id: Map.get(attrs, :ca_instance_id),
          prev_hash: prev_hash
        }

        event_hash = PkiAuditTrail.Hasher.compute_hash(event_attrs)
        full_attrs = Map.put(event_attrs, :event_hash, event_hash)
        changeset = PkiAuditTrail.AuditEvent.changeset(%PkiAuditTrail.AuditEvent{}, full_attrs)

        case PlatformRepo.insert(changeset, prefix: prefix) do
          {:ok, _event} ->
            PkiAuditTrail.HashChainStore.update(tenant_id, event_hash)
            :ok

          {:error, reason} ->
            Logger.warning("[platform_audit] per-tenant audit failed tenant_id=#{tenant_id} reason=#{inspect(reason)}")
            :ok
        end

      _ ->
        :ok
    end
  rescue
    e ->
      Logger.warning("[platform_audit] per-tenant audit exception tenant_id=#{tenant_id} error=#{Exception.message(e)}")
      :ok
  end

  defp infer_resource_type(action) do
    cond do
      String.contains?(action, "cert") -> "certificate"
      String.contains?(action, "csr") -> "csr"
      String.contains?(action, "ceremony") -> "ceremony"
      String.contains?(action, "issuer_key") or String.contains?(action, "key") -> "issuer_key"
      String.contains?(action, "ca_instance") -> "ca_instance"
      String.contains?(action, "keystore") -> "keystore"
      String.contains?(action, "user") or String.contains?(action, "profile") or
          String.contains?(action, "password") -> "user"
      String.contains?(action, "api_key") -> "api_key"
      true -> "general"
    end
  end

  @doc """
  Query audit events with filters.

  ## Filters
    * `:tenant_id` — filter by tenant
    * `:portal` — filter by portal ("ca", "ra", "admin")
    * `:action` — filter by action
    * `:actor_username` — filter by actor (partial match)
    * `:date_from` — filter from date (ISO 8601 string or Date)
    * `:date_to` — filter to date (ISO 8601 string or Date)
    * `:limit` — max results (default 200)
  """
  def list_events(filters \\ []) do
    limit = Keyword.get(filters, :limit, 200)

    query =
      from(e in PlatformAuditEvent,
        order_by: [desc: e.timestamp],
        limit: ^limit
      )

    query = Enum.reduce(filters, query, fn
      {:tenant_id, tid}, q when is_binary(tid) and tid != "" ->
        from(e in q, where: e.tenant_id == ^tid)

      {:portal, portal}, q when is_binary(portal) and portal != "" ->
        from(e in q, where: e.portal == ^portal)

      {:action, action}, q when is_binary(action) and action != "" ->
        from(e in q, where: e.action == ^action)

      {:actor_username, actor}, q when is_binary(actor) and actor != "" ->
        escaped = actor |> String.replace("\\", "\\\\") |> String.replace("%", "\\%") |> String.replace("_", "\\_")
        from(e in q, where: ilike(e.actor_username, ^"%#{escaped}%"))

      {:date_from, date_str}, q when is_binary(date_str) and date_str != "" ->
        case Date.from_iso8601(date_str) do
          {:ok, date} ->
            dt = DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
            from(e in q, where: e.timestamp >= ^dt)
          _ -> q
        end

      {:date_to, date_str}, q when is_binary(date_str) and date_str != "" ->
        case Date.from_iso8601(date_str) do
          {:ok, date} ->
            dt = DateTime.new!(date, ~T[23:59:59], "Etc/UTC")
            from(e in q, where: e.timestamp <= ^dt)
          _ -> q
        end

      _, q -> q
    end)

    PlatformRepo.all(query)
  end
end
