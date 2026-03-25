defmodule PkiRaPortalWeb.SessionController do
  use PkiRaPortalWeb, :controller
  import Plug.Conn

  alias PkiRaPortal.RaEngineClient

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    case RaEngineClient.authenticate(username, password) do
      {:ok, user} ->
        conn
        |> configure_session(renew: true)
        |> put_session(:current_user, %{
          id: user.id,
          username: user.username,
          role: user.role,
          display_name: user.display_name
        })
        |> redirect(to: "/")

      {:error, :invalid_credentials} ->
        render(conn, :login, layout: false, error: "Invalid username or password")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
