defmodule PkiPlatformPortalWeb.SessionController do
  use PkiPlatformPortalWeb, :controller

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"username" => username, "password" => password}) do
    # TODO: Implement real authentication against platform admin users
    if username == "admin" && password == "admin" do
      conn
      |> put_session(:current_user, %{"username" => username, "display_name" => "Platform Admin"})
      |> redirect(to: "/")
    else
      render(conn, :login, layout: false, error: "Invalid username or password")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
