defmodule PkiCaPortalWeb.SessionController do
  use PkiCaPortalWeb, :controller
  import Plug.Conn

  alias PkiCaPortal.CaEngineClient

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password} = params}) do
    ca_instance_id = parse_instance_id(params["ca_instance_id"])

    case CaEngineClient.authenticate_with_session(username, password) do
      {:ok, user, session_info} ->
        tenant_id = user[:tenant_id]

        cond do
          user[:must_change_password] && credential_expired?(user) ->
            render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact your platform administrator.")

          user[:must_change_password] ->
            conn
            |> configure_session(renew: true)
            |> put_session(:current_user, serialize_user(user, ca_instance_id))
            |> put_session(:tenant_id, tenant_id)
            |> put_session(:session_key, session_info[:session_key])
            |> put_session(:session_salt, session_info[:session_salt])
            |> put_session(:must_change_password, true)
            |> redirect(to: "/change-password")

          true ->
            conn
            |> configure_session(renew: true)
            |> put_session(:current_user, serialize_user(user, ca_instance_id))
            |> put_session(:tenant_id, tenant_id)
            |> put_session(:session_key, session_info[:session_key])
            |> put_session(:session_salt, session_info[:session_salt])
            |> redirect(to: "/")
        end

      {:error, :invalid_credentials} ->
        render(conn, :login, layout: false, error: "Invalid username or password")

      {:error, reason} ->
        require Logger
        Logger.error("Authentication error: #{inspect(reason)}")
        render(conn, :login, layout: false, error: "Service unavailable. Please try again.")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end

  defp serialize_user(user, ca_instance_id) do
    %{
      id: user[:id],
      username: user[:username],
      role: user[:role],
      display_name: user[:display_name],
      ca_instance_id: user[:ca_instance_id] || ca_instance_id,
      tenant_id: user[:tenant_id]
    }
  end

  defp credential_expired?(%{credential_expires_at: nil}), do: false
  defp credential_expired?(%{credential_expires_at: expires_at}) when is_binary(expires_at) do
    case DateTime.from_iso8601(expires_at) do
      {:ok, dt, _} -> DateTime.compare(DateTime.utc_now(), dt) == :gt
      _ -> false
    end
  end
  defp credential_expired?(%{credential_expires_at: %DateTime{} = expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
  defp credential_expired?(_), do: false

  defp parse_instance_id(nil), do: "default"
  defp parse_instance_id(val) when is_binary(val), do: val
  defp parse_instance_id(val) when is_integer(val), do: Integer.to_string(val)
  defp parse_instance_id(_), do: "default"
end
