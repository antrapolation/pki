defmodule PkiPlatformPortalWeb.SessionController do
  use PkiPlatformPortalWeb, :controller
  import Plug.Conn

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    expected_user = Application.get_env(:pki_platform_portal, :admin_username, "admin")
    expected_hash = Application.get_env(:pki_platform_portal, :admin_password_hash)

    if Plug.Crypto.secure_compare(username, expected_user) and
         is_binary(expected_hash) and Argon2.verify_pass(password, expected_hash) do
      conn
      |> configure_session(renew: true)
      |> put_session(:current_user, %{
        "username" => username,
        "display_name" => "Platform Admin",
        "role" => "platform_admin"
      })
      |> put_session(:platform_admin, true)
      |> redirect(to: "/")
    else
      render(conn, :login, layout: false, error: "Invalid credentials")
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
