defmodule PkiCaEngine.Api.UserController do
  @moduledoc """
  Handles user CRUD endpoints.
  """

  import Plug.Conn
  alias PkiCaEngine.UserManagement
  alias PkiCaEngine.Api.Helpers

  def index(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.query_params)
    opts = if role = conn.query_params["role"], do: [role: role], else: []
    users = UserManagement.list_users(ca_instance_id, opts)
    json(conn, 200, Enum.map(users, &serialize_user/1))
  end

  def create(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.body_params)
    attrs = build_attrs(conn.body_params)
    password = conn.body_params["password"]

    result =
      if password do
        # Create user with cryptographic credentials
        user_attrs = Map.drop(attrs, [:password, "password"])
        opts = build_admin_context(conn.body_params)
        UserManagement.create_user_with_credentials(ca_instance_id, user_attrs, password, opts)
      else
        # Legacy: create user without credentials
        UserManagement.create_user(ca_instance_id, attrs)
      end

    case result do
      {:ok, user} ->
        json(conn, 201, serialize_user(user))

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        json(conn, 422, %{error: "validation_error", details: %{base: [inspect(reason)]}})
    end
  end

  def show(conn, id) do
    case UserManagement.get_user(id) do
      {:ok, user} -> json(conn, 200, serialize_user(user))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  def update_password(conn, id) do
    password = conn.body_params["password"]
    must_change = conn.body_params["must_change_password"]

    case UserManagement.get_user(id) do
      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})

      {:ok, user} ->
        attrs = %{password: password}
        attrs = if must_change != nil, do: Map.put(attrs, :must_change_password, must_change), else: attrs

        case UserManagement.update_user_password(user, attrs) do
          {:ok, _user} -> json(conn, 200, %{status: "ok"})
          {:error, changeset} -> json(conn, 422, %{errors: changeset_errors(changeset)})
        end
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
    |> maybe_put(:ca_instance_id, params["ca_instance_id"])
    |> maybe_put(:must_change_password, params["must_change_password"])
    |> maybe_put(:credential_expires_at, params["credential_expires_at"])
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
