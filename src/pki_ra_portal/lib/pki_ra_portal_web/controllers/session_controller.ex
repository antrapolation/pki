defmodule PkiRaPortalWeb.SessionController do
  use PkiRaPortalWeb, :controller
  import Plug.Conn

  alias PkiRaPortal.RaEngineClient

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    case RaEngineClient.authenticate_with_session(username, password) do
      {:ok, user, session} ->
        cond do
          tenant_suspended?(user) ->
            render(conn, :login, layout: false, error: "Your organization's account has been suspended.")

          user[:must_change_password] && credential_expired?(user) ->
            render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact your platform administrator.")

          user[:must_change_password] ->
            conn
            |> configure_session(renew: true)
            |> put_session(:current_user, serialize_user(user))
            |> put_session(:session_key, session.session_key)
            |> put_session(:session_salt, session.session_salt)
            |> put_session(:must_change_password, true)
            |> redirect(to: "/change-password")

          true ->
            conn
            |> configure_session(renew: true)
            |> put_session(:current_user, serialize_user(user))
            |> put_session(:session_key, session.session_key)
            |> put_session(:session_salt, session.session_salt)
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

  defp serialize_user(user) do
    %{
      id: user[:id],
      username: user[:username],
      role: user[:role],
      display_name: user[:display_name],
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

  defp tenant_suspended?(%{tenant_id: nil}), do: false
  defp tenant_suspended?(%{tenant_id: tenant_id}) do
    case PkiPlatformEngine.Provisioner.get_tenant(tenant_id) do
      %{status: "suspended"} -> true
      _ -> false
    end
  rescue
    _ -> false
  end
  defp tenant_suspended?(_), do: false
end
