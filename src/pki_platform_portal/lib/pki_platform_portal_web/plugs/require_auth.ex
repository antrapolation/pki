defmodule PkiPlatformPortalWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that requires the user to be authenticated.
  Redirects to /login if no session user is found.
  """
  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    if get_session(conn, :current_user) do
      assign(conn, :current_user, get_session(conn, :current_user))
    else
      conn
      |> put_flash(:error, "You must log in to access this page.")
      |> redirect(to: "/login")
      |> halt()
    end
  end
end
