defmodule PkiRaPortalWeb.Plugs.RequireAuthTest do
  use PkiRaPortalWeb.ConnCase

  alias PkiRaPortalWeb.Plugs.RequireAuth

  describe "call/2" do
    test "redirects to /login when no current_user in session", %{conn: conn} do
      conn =
        conn
        |> init_test_session(%{})
        |> fetch_flash()
        |> RequireAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/login"
    end

    test "assigns current_user when present in session", %{conn: conn} do
      user = %{id: 1, username: "raadmin1", role: "ra_admin"}

      conn =
        conn
        |> init_test_session(%{current_user: user})
        |> RequireAuth.call([])

      refute conn.halted
      assert conn.assigns[:current_user] == user
    end
  end
end
