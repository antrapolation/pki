defmodule PkiRaPortalWeb.SessionController do
  use PkiRaPortalWeb, :controller
  import Plug.Conn

  def new(conn, _params) do
    render(conn, :login, layout: false)
  end

  def create(conn, %{"session" => session_params}) do
    user = %{
      did: session_params["did"],
      role: session_params["role"]
    }

    conn
    |> configure_session(renew: true)
    |> put_session(:current_user, user)
    |> redirect(to: "/")
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
