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
    password = conn.body_params["password"]

    if password do
      # Create user with credential keypairs
      opts = build_admin_context(conn.body_params)
      case UserManagement.create_user_with_credentials(attrs, password, opts) do
        {:ok, user} ->
          json(conn, 201, Map.merge(serialize_user(user), %{has_credentials: true}))

        {:error, %Ecto.Changeset{} = changeset} ->
          json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})

        {:error, reason} ->
          json(conn, 422, %{error: "credential_error", message: inspect(reason)})
      end
    else
      # Legacy: create user without credentials
      case UserManagement.create_user(attrs) do
        {:ok, user} ->
          json(conn, 201, Map.merge(serialize_user(user), %{has_credentials: false}))

        {:error, %Ecto.Changeset{} = changeset} ->
          json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
      end
    end
  end

  def delete(conn, id) do
    case UserManagement.delete_user(id) do
      {:ok, user} -> json(conn, 200, serialize_user(user))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  defp build_filters(query_params) do
    []
    |> maybe_add_filter(query_params, "role", :role)
    |> maybe_add_filter(query_params, "status", :status)
    |> maybe_add_filter(query_params, "tenant_id", :tenant_id)
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
    |> maybe_put(:status, params["status"])
    |> maybe_put(:tenant_id, params["tenant_id"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp build_admin_context(%{"admin_user_id" => admin_id, "admin_password" => admin_pw})
       when is_binary(admin_id) and is_binary(admin_pw) do
    [admin_context: %{user_id: admin_id, password: admin_pw}]
  end

  defp build_admin_context(_), do: []

  defp serialize_user(user) do
    %{
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      role: user.role,
      status: user.status,
      tenant_id: user.tenant_id,
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
