defmodule PkiPlatformPortalWeb.Plugs.RequireSetup do
  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    if PkiPlatformEngine.AdminManagement.needs_setup?() do
      conn
      |> redirect(to: "/setup")
      |> halt()
    else
      conn
    end
  end
end
