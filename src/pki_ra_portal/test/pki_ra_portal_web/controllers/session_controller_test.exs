defmodule PkiRaPortalWeb.SessionControllerTest do
  use PkiRaPortalWeb.ConnCase

  describe "GET /login" do
    test "renders login form", %{conn: conn} do
      conn = get(conn, ~p"/login")
      assert html_response(conn, 200) =~ "RA Admin Portal Login"
      assert html_response(conn, 200) =~ "session[did]"
      assert html_response(conn, 200) =~ "session[role]"
    end
  end

  describe "POST /login" do
    test "sets session and redirects to home", %{conn: conn} do
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "did" => "did:ssdid:testadmin",
            "role" => "ra_admin"
          }
        })

      assert redirected_to(conn) == "/"

      # Follow redirect with the session cookie
      conn = get(recycle(conn), ~p"/")
      assert html_response(conn, 200) =~ "Dashboard"
    end
  end

  describe "DELETE /logout" do
    test "clears session and redirects to login", %{conn: conn} do
      user = %{did: "did:ssdid:raadmin1", role: "ra_admin"}

      conn =
        conn
        |> init_test_session(%{current_user: user})
        |> delete(~p"/logout")

      assert redirected_to(conn) == "/login"

      # After logout, accessing / should redirect to login
      conn = get(recycle(conn), ~p"/")
      assert redirected_to(conn) == "/login"
    end
  end
end
