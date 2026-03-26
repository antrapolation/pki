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
        conn
        |> configure_session(renew: true)
        |> put_session(:current_user, %{
          id: user.id,
          username: user.username,
          role: user.role,
          display_name: user.display_name
        })
        |> put_session(:session_key, session.session_key)
        |> put_session(:session_salt, session.session_salt)
        |> redirect(to: "/")

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
end
