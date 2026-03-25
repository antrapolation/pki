defmodule PkiRaEngine.Api.UserController do
  @moduledoc """
  Handles user CRUD endpoints (protected by InternalAuthPlug).
  """

  import Plug.Conn
  alias PkiRaEngine.UserManagement

  def index(conn) do
    opts = build_filters(conn.query_params)
    users = UserManagement.list_users(opts)
    json(conn, 200, Enum.map(users, &serialize_user/1))
  end

  def create(conn) do
    attrs = build_attrs(conn.body_params)

    case UserManagement.create_user(attrs) do
      {:ok, user} ->
        json(conn, 201, serialize_user(user))

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def delete(conn, id) do
    case UserManagement.delete_user(String.to_integer(id)) do
      {:ok, user} -> json(conn, 200, serialize_user(user))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  defp build_filters(query_params) do
    []
    |> maybe_add_filter(query_params, "role", :role)
    |> maybe_add_filter(query_params, "status", :status)
  end

  defp maybe_add_filter(filters, params, key, filter_key) do
    case Map.get(params, key) do
      nil -> filters
      value -> [{filter_key, value} | filters]
    end
  end

  defp build_attrs(params) do
    %{}
    |> maybe_put(:username, params["username"])
    |> maybe_put(:password, params["password"])
    |> maybe_put(:display_name, params["display_name"])
    |> maybe_put(:role, params["role"])
    |> maybe_put(:did, params["did"])
    |> maybe_put(:status, params["status"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp serialize_user(user) do
    %{
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      role: user.role,
      status: user.status,
      did: user.did,
      inserted_at: user.inserted_at,
      updated_at: user.updated_at
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
