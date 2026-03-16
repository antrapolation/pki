defmodule PkiCaPortalWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that redirects unauthenticated users to the login page.

  Expects `:current_user` to be set in the session. If present,
  it assigns the user to the connection for downstream use.
  """

  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_session(conn, :current_user) do
      nil ->
        conn
        |> redirect(to: "/login")
        |> halt()

      user ->
        assign(conn, :current_user, user)
    end
  end
end
