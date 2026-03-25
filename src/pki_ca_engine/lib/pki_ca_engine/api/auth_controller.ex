defmodule PkiCaEngine.Api.AuthController do
  @moduledoc """
  Handles public authentication endpoints (login, register, needs-setup).
  These do not require an API secret.
  """

  import Plug.Conn
  alias PkiCaEngine.UserManagement

  def login(conn) do
    with %{"username" => username, "password" => password} <- conn.body_params,
         {:ok, user} <- UserManagement.authenticate(username, password) do
      json(conn, 200, serialize_user(user))
    else
      {:error, :invalid_credentials} ->
        json(conn, 401, %{error: "invalid_credentials"})

      _ ->
        json(conn, 400, %{error: "bad_request", message: "username and password required"})
    end
  end

  def register(conn) do
    with %{"ca_instance_id" => ca_instance_id} <- conn.body_params do
      attrs = build_user_attrs(conn.body_params)

      case UserManagement.register_user(ca_instance_id, attrs) do
        {:ok, user} ->
          json(conn, 201, serialize_user(user))

        {:error, :setup_already_complete} ->
          json(conn, 409, %{error: "setup_already_complete"})

        {:error, %Ecto.Changeset{} = changeset} ->
          json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
      end
    else
      _ ->
        json(conn, 400, %{error: "bad_request", message: "ca_instance_id required"})
    end
  end

  def needs_setup(conn) do
    case conn.query_params do
      %{"ca_instance_id" => ca_instance_id_str} ->
        ca_instance_id = String.to_integer(ca_instance_id_str)
        json(conn, 200, %{needs_setup: UserManagement.needs_setup?(ca_instance_id)})

      _ ->
        json(conn, 400, %{error: "bad_request", message: "ca_instance_id query param required"})
    end
  end

  defp build_user_attrs(params) do
    %{}
    |> maybe_put(:username, params["username"])
    |> maybe_put(:password, params["password"])
    |> maybe_put(:display_name, params["display_name"])
    |> maybe_put(:role, params["role"])
    |> maybe_put(:did, params["did"])
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
