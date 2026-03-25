defmodule PkiCaEngine.Api.StatusController do
  @moduledoc """
  Handles engine status endpoint.
  """

  import Plug.Conn
  alias PkiCaEngine.IssuerKeyManagement

  def show(conn) do
    case conn.query_params do
      %{"ca_instance_id" => ca_instance_id_str} ->
        ca_instance_id = String.to_integer(ca_instance_id_str)
        issuer_keys = IssuerKeyManagement.list_issuer_keys(ca_instance_id)

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

      _ ->
        json(conn, 400, %{error: "bad_request", message: "ca_instance_id query param required"})
    end
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
