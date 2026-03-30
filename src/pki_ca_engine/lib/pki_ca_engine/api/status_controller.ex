defmodule PkiCaEngine.Api.StatusController do
  @moduledoc """
  Handles engine status endpoint.
  """

  import Plug.Conn
  alias PkiCaEngine.IssuerKeyManagement
  alias PkiCaEngine.Api.Helpers

  def show(conn) do
    tenant_id = conn.assigns[:tenant_id]
    ca_instance_id = Helpers.resolve_instance_id(conn.query_params)
    issuer_keys = IssuerKeyManagement.list_issuer_keys(tenant_id, ca_instance_id)

    active_keys = Enum.count(issuer_keys, &(&1.status == "active"))
    total_keys = length(issuer_keys)
    uptime_seconds = System.monotonic_time(:second)

    json(conn, 200, %{
      status: "running",
      ca_instance_id: ca_instance_id,
      issuer_keys: %{
        total: total_keys,
        active: active_keys
      },
      uptime_seconds: uptime_seconds
    })
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
