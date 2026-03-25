defmodule PkiCaEngine.Api.AuditLogController do
  @moduledoc """
  Handles audit log query endpoint.

  Queries the PkiAuditTrail module to fetch real audit events with support
  for filtering by action, actor_did, date_from, and date_to.
  """

  require Logger
  import Plug.Conn

  def index(conn) do
    filters = build_filters(conn.query_params)

    case safe_query(filters) do
      {:ok, events} ->
        data =
          Enum.map(events, fn event ->
            %{
              id: event.id,
              event_id: event.event_id,
              timestamp: event.timestamp,
              node_name: event.node_name,
              actor_did: event.actor_did,
              actor_role: event.actor_role,
              action: event.action,
              resource_type: event.resource_type,
              resource_id: event.resource_id,
              details: event.details
            }
          end)

        json(conn, 200, %{data: data})

      {:error, reason} ->
        Logger.error("Audit log query failed: #{inspect(reason)}")
        json(conn, 500, %{error: "audit_query_failed"})
    end
  end

  defp build_filters(query_params) do
    []
    |> maybe_add_filter(:action, query_params["action"])
    |> maybe_add_filter(:actor_did, query_params["actor_did"])
    |> maybe_add_filter(:resource_type, query_params["resource_type"])
    |> maybe_add_filter(:resource_id, query_params["resource_id"])
    |> maybe_add_date_filter(:since, query_params["date_from"])
    |> maybe_add_date_filter(:until, query_params["date_to"])
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, _key, ""), do: filters
  defp maybe_add_filter(filters, key, value), do: [{key, value} | filters]

  defp maybe_add_date_filter(filters, _key, nil), do: filters
  defp maybe_add_date_filter(filters, _key, ""), do: filters

  defp maybe_add_date_filter(filters, key, date_string) do
    case DateTime.from_iso8601(date_string) do
      {:ok, datetime, _offset} ->
        [{key, datetime} | filters]

      {:error, _} ->
        # Try parsing as date only (YYYY-MM-DD)
        case Date.from_iso8601(date_string) do
          {:ok, date} ->
            datetime =
              case key do
                :since -> DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
                :until -> DateTime.new!(date, ~T[23:59:59], "Etc/UTC")
              end

            [{key, datetime} | filters]

          {:error, _} ->
            Logger.warning("Invalid date filter #{key}: #{inspect(date_string)}")
            filters
        end
    end
  end

  defp safe_query(filters) do
    {:ok, PkiAuditTrail.query(filters)}
  rescue
    e ->
      Logger.error("Audit trail query error: #{Exception.message(e)}")
      {:error, :query_failed}
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
