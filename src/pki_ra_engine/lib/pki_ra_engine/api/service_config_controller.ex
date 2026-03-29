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

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  defp serialize_config(config) do
    %{
      id: config.id,
      service_type: config.service_type,
      port: config.port,
      url: config.url,
      rate_limit: config.rate_limit,
      ip_whitelist: config.ip_whitelist,
      ip_blacklist: config.ip_blacklist,
      connection_security: config.connection_security,
      ca_engine_ref: config.ca_engine_ref,
      status: "active",
      inserted_at: config.inserted_at,
      updated_at: config.updated_at
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
