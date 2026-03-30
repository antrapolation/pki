defmodule PkiPlatformPortalWeb.SessionController do
  use PkiPlatformPortalWeb, :controller

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    case PkiPlatformEngine.AdminManagement.authenticate(username, password) do
      {:ok, admin} ->
        conn
        |> put_session(:current_user, %{
          "id" => admin.id,
          "username" => admin.username,
          "display_name" => admin.display_name,
          "role" => admin.role
        })
        |> redirect(to: "/")

      {:error, _} ->
        render(conn, :login, layout: false, error: "Invalid credentials")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
