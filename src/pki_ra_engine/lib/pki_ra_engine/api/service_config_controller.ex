defmodule PkiRaEngine.Api.ServiceConfigController do
  @moduledoc """
  Handles service config endpoints (protected by InternalAuthPlug).
  """

  import Plug.Conn
  alias PkiRaEngine.ServiceConfig

  def index(conn) do
    configs = ServiceConfig.list_service_configs()
    json(conn, 200, Enum.map(configs, &serialize_config/1))
  end

  def upsert(conn) do
    case ServiceConfig.configure_service(conn.body_params) do
      {:ok, config} ->
        json(conn, 200, serialize_config(config))

      {:error, :invalid_service_type} ->
        json(conn, 422, %{error: "invalid_service_type"})

      {:error, :service_type_required} ->
        json(conn, 422, %{error: "service_type_required"})

      {:error, reason} ->
        json(conn, 500, %{error: "internal_error", reason: inspect(reason)})
    end
  end

  defp serialize_config(config) do
    %{
      id: config.id,
      service_type: config.service_type,
      port: config.port,
      url: config.url,
      status: config.status,
      inserted_at: config.inserted_at,
      updated_at: config.updated_at
    }
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
