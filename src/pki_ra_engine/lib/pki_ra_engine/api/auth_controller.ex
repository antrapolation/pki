defmodule PkiRaEngine.Api.AuthController do
  @moduledoc """
  Handles public authentication endpoints (login, register, needs-setup).
  These do not require a Bearer token.
  """

  import Plug.Conn
  alias PkiRaEngine.UserManagement

  def login(conn) do
    with %{"username" => username, "password" => password} <- conn.body_params,
         {:ok, user, session_info} <- UserManagement.authenticate_with_credentials(username, password) do
      json(conn, 200, Map.merge(serialize_user(user), %{
        session_key: Base.encode64(session_info.session_key),
        session_salt: Base.encode64(session_info.session_salt),
        has_credentials: true
      }))
    else
      {:error, :invalid_credentials} ->
        # Fallback to password-only auth for users without credentials
        with %{"username" => username, "password" => password} <- conn.body_params,
             {:ok, user} <- UserManagement.authenticate(username, password) do
          json(conn, 200, Map.merge(serialize_user(user), %{has_credentials: false}))
        else
          {:error, :invalid_credentials} ->
            json(conn, 401, %{error: "invalid_credentials"})

          _ ->
            json(conn, 401, %{error: "invalid_credentials"})
        end

      _ ->
        json(conn, 400, %{error: "bad_request", message: "username and password required"})
    end
  end

  def register(conn) do
    attrs = build_user_attrs(conn.body_params)

    case UserManagement.register_user(attrs) do
      {:ok, user} ->
        json(conn, 201, serialize_user(user))

      {:error, :username_taken} ->
        json(conn, 409, %{error: "username_taken"})

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        json(conn, 422, %{error: inspect(reason)})
    end
  end

  def needs_setup(conn) do
    json(conn, 200, %{needs_setup: UserManagement.needs_setup?()})
  end

  defp build_user_attrs(params) do
    %{}
    |> maybe_put(:username, params["username"])
    |> maybe_put(:password, params["password"])
    |> maybe_put(:display_name, params["display_name"])
    |> maybe_put(:role, params["role"])
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
