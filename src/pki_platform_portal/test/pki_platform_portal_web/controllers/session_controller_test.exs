defmodule PkiPlatformPortalWeb.SessionControllerTest do
  use PkiPlatformPortalWeb.ConnCase

  describe "GET /login" do
    test "renders login form", %{conn: conn} do
      conn = get(conn, ~p"/login")
      assert html_response(conn, 200) =~ "Platform Admin"
      assert html_response(conn, 200) =~ "session[username]"
      assert html_response(conn, 200) =~ "session[password]"
    end
  end

  describe "POST /login" do
    test "redirects to home with valid credentials", %{conn: conn} do
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "username" => "admin",
            "password" => "admin"
          }
        })

      assert redirected_to(conn) == "/"

      # Follow redirect with session cookie
      conn = get(recycle(conn), ~p"/")
      assert html_response(conn, 200) =~ "Dashboard"
    end

    test "renders error with invalid credentials", %{conn: conn} do
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "username" => "admin",
            "password" => "wrong"
          }
        })

      assert html_response(conn, 200) =~ "Invalid credentials"
    end

    test "renders error with wrong username", %{conn: conn} do
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "username" => "notadmin",
            "password" => "admin"
          }
        })

      assert html_response(conn, 200) =~ "Invalid credentials"
    end
  end

  describe "DELETE /logout" do
    test "clears session and redirects to login", %{conn: conn} do
      user = %{"username" => "admin", "display_name" => "Platform Admin", "role" => "platform_admin"}

      conn =
        conn
        |> init_test_session(%{current_user: user})
        |> delete(~p"/logout")

      assert redirected_to(conn) == "/login"

      # After logout, accessing / should redirect to login
      conn = get(recycle(conn), ~p"/")
      assert redirected_to(conn) == "/login"
    end

    test "redirects to /login even when not logged in", %{conn: conn} do
      conn = delete(conn, ~p"/logout")
      assert redirected_to(conn) == "/login"
    end
  end
end
