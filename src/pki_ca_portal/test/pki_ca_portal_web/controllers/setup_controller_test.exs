defmodule PkiCaPortalWeb.SetupControllerTest do
  use PkiCaPortalWeb.ConnCase

  describe "GET /setup" do
    test "redirects to /login when system is already configured", %{conn: conn} do
      conn = get(conn, ~p"/setup")
      assert redirected_to(conn) == "/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "already configured"
    end
  end

  describe "POST /setup" do
    test "redirects to /login when system is already configured", %{conn: conn} do
      conn =
        post(conn, ~p"/setup", %{
          "setup" => %{
            "username" => "newadmin",
            "display_name" => "New Admin",
            "password" => "securepassword123",
            "password_confirmation" => "securepassword123"
          }
        })

      assert redirected_to(conn) == "/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "already configured"
    end

    test "POST /setup with empty params also redirects when configured", %{conn: conn} do
      conn = post(conn, ~p"/setup", %{"setup" => %{}})
      assert redirected_to(conn) == "/login"
    end
  end
end
