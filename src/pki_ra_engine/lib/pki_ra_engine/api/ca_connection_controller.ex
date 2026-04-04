defmodule PkiRaEngine.Api.CaConnectionController do
  @moduledoc """
  REST API controller for managing CA-to-RA connections.
  """

  import Plug.Conn
  require Logger
  alias PkiRaEngine.CaConnectionManagement

  def index(conn) do
    tenant_id = conn.assigns[:tenant_id]

    case conn.query_params["ra_instance_id"] do
      nil ->
        json(conn, 400, %{error: "missing_parameter", parameter: "ra_instance_id"})

      ra_instance_id ->
        connections = CaConnectionManagement.list_connections(tenant_id, ra_instance_id)
        json(conn, 200, Enum.map(connections, &serialize/1))
    end
  end

  def create(conn) do
    tenant_id = conn.assigns[:tenant_id]
    ra_instance_id = conn.body_params["ra_instance_id"]

    # connected_by comes from the authenticated session, not the request body
    connected_by = case conn.assigns do
      %{current_api_key: api_key} -> api_key.ra_user_id
      _ -> nil
    end

    attrs = %{
      issuer_key_id: conn.body_params["issuer_key_id"],
      issuer_key_name: conn.body_params["issuer_key_name"],
      algorithm: conn.body_params["algorithm"],
      ca_instance_name: conn.body_params["ca_instance_name"],
      connected_by: connected_by
    }

    case CaConnectionManagement.connect(tenant_id, ra_instance_id, attrs) do
      {:ok, connection} ->
        json(conn, 201, serialize(connection))

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        Logger.error("ca_connection_create_failed reason=#{inspect(reason)}")
        json(conn, 400, %{error: "create_failed"})
    end
  end

  def delete(conn, id) do
    tenant_id = conn.assigns[:tenant_id]

    case CaConnectionManagement.disconnect(tenant_id, id) do
      {:ok, connection} -> json(conn, 200, serialize(connection))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  def connected_keys(conn) do
    tenant_id = conn.assigns[:tenant_id]
    keys = CaConnectionManagement.list_connected_issuer_keys(tenant_id)
    json(conn, 200, keys)
  end

  defp serialize(conn_record) do
    %{
      id: conn_record.id,
      ra_instance_id: conn_record.ra_instance_id,
      issuer_key_id: conn_record.issuer_key_id,
      issuer_key_name: conn_record.issuer_key_name,
      algorithm: conn_record.algorithm,
      ca_instance_name: conn_record.ca_instance_name,
      status: conn_record.status,
      connected_at: conn_record.connected_at && DateTime.to_iso8601(conn_record.connected_at),
      connected_by: conn_record.connected_by,
      inserted_at: conn_record.inserted_at,
      updated_at: conn_record.updated_at
    }
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
