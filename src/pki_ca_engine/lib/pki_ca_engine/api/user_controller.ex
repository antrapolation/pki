defmodule PkiCaEngine.Api.UserController do
  @moduledoc """
  Handles user CRUD endpoints.
  """

  import Plug.Conn
  alias PkiCaEngine.UserManagement

  def index(conn) do
    case conn.query_params do
      %{"ca_instance_id" => ca_instance_id} ->
        opts = if role = conn.query_params["role"], do: [role: role], else: []
        users = UserManagement.list_users(ca_instance_id, opts)
        json(conn, 200, %{data: Enum.map(users, &serialize_user/1)})

      _ ->
        json(conn, 400, %{error: "bad_request", message: "ca_instance_id query param required"})
    end
  end

  def create(conn) do
    with %{"ca_instance_id" => ca_instance_id} <- conn.body_params do
      attrs = build_attrs(conn.body_params)

      case UserManagement.create_user(ca_instance_id, attrs) do
        {:ok, user} ->
          json(conn, 201, serialize_user(user))

        {:error, %Ecto.Changeset{} = changeset} ->
          json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
      end
    else
      _ ->
        json(conn, 400, %{error: "bad_request", message: "ca_instance_id required"})
    end
  end

  def show(conn, id) do
    case UserManagement.get_user(id) do
      {:ok, user} -> json(conn, 200, serialize_user(user))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  def delete(conn, id) do
    case UserManagement.delete_user(id) do
      {:ok, user} -> json(conn, 200, serialize_user(user))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  defp build_attrs(params) do
    %{}
    |> maybe_put(:username, params["username"])
    |> maybe_put(:password, params["password"])
    |> maybe_put(:display_name, params["display_name"])
    |> maybe_put(:role, params["role"])
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
      ca_instance_id: user.ca_instance_id,
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
