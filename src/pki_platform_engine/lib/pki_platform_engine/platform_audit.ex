defmodule PkiPlatformEngine.PlatformAudit do
  @moduledoc """
  Audit logging for platform-level operations: authentication, user management, profile changes.
  Writes to the platform_audit_events table in the platform DB.
  """

  import Ecto.Query
  alias PkiPlatformEngine.{PlatformRepo, PlatformAuditEvent}

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
    %PlatformAuditEvent{}
    |> PlatformAuditEvent.changeset(
      Map.merge(attrs, %{
        action: action,
        timestamp: DateTime.utc_now()
      })
    )
    |> PlatformRepo.insert()
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
        from(e in q, where: ilike(e.actor_username, ^"%#{actor}%"))

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
