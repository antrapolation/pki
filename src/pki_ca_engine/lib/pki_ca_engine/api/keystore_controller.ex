defmodule PkiCaEngine.Api.KeystoreController do
  @moduledoc """
  Handles keystore management endpoints.
  """

  import Plug.Conn
  alias PkiCaEngine.KeystoreManagement

  def index(conn) do
    case conn.query_params do
      %{"ca_instance_id" => ca_instance_id_str} ->
        ca_instance_id = String.to_integer(ca_instance_id_str)
        keystores = KeystoreManagement.list_keystores(ca_instance_id)
        json(conn, 200, %{data: Enum.map(keystores, &serialize_keystore/1)})

      _ ->
        json(conn, 400, %{error: "bad_request", message: "ca_instance_id query param required"})
    end
  end

  def create(conn) do
    with %{"ca_instance_id" => ca_instance_id} <- conn.body_params do
      attrs = build_attrs(conn.body_params)

      case KeystoreManagement.configure_keystore(ca_instance_id, attrs) do
        {:ok, keystore} ->
          json(conn, 201, serialize_keystore(keystore))

        {:error, %Ecto.Changeset{} = changeset} ->
          json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
      end
    else
      _ ->
        json(conn, 400, %{error: "bad_request", message: "ca_instance_id required"})
    end
  end

  defp build_attrs(params) do
    %{}
    |> maybe_put(:type, params["type"])
    |> maybe_put(:config, params["config"])
    |> maybe_put(:status, params["status"])
    |> maybe_put(:provider_name, params["provider_name"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp serialize_keystore(keystore) do
    %{
      id: keystore.id,
      type: keystore.type,
      status: keystore.status,
      provider_name: keystore.provider_name,
      ca_instance_id: keystore.ca_instance_id,
      inserted_at: keystore.inserted_at,
      updated_at: keystore.updated_at
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
