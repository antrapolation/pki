defmodule PkiCaEngine.Api.KeystoreController do
  @moduledoc """
  Handles keystore management endpoints.
  """

  import Plug.Conn
  alias PkiCaEngine.KeystoreManagement
  alias PkiCaEngine.Api.Helpers

  def index(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.query_params)
    keystores = KeystoreManagement.list_keystores(ca_instance_id)
    json(conn, 200, Enum.map(keystores, &serialize_keystore/1))
  end

  def create(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.body_params)
    attrs = build_attrs(conn.body_params)

    case KeystoreManagement.configure_keystore(ca_instance_id, attrs) do
      {:ok, keystore} ->
        json(conn, 201, serialize_keystore(keystore))

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
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
