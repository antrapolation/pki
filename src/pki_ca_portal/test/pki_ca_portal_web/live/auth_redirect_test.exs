defmodule PkiCaPortalWeb.AuthRedirectTest do
  use PkiCaPortalWeb.ConnCase
  import Phoenix.LiveViewTest

  @protected_routes ["/", "/ceremony", "/users", "/keystores", "/audit-log"]

  for route <- @protected_routes do
    test "unauthenticated request to #{route} redirects to /login", %{conn: conn} do
      assert {:error, {:redirect, %{to: "/login"}}} = live(conn, unquote(route))
    end
  end
end
