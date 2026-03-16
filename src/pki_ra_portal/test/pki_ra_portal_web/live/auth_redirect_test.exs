defmodule PkiRaPortalWeb.AuthRedirectTest do
  use PkiRaPortalWeb.ConnCase
  import Phoenix.LiveViewTest

  @protected_routes ["/", "/csrs", "/users", "/cert-profiles", "/service-configs", "/api-keys"]

  for route <- @protected_routes do
    test "unauthenticated request to #{route} redirects to /login", %{conn: conn} do
      assert {:error, {:redirect, %{to: "/login"}}} = live(conn, unquote(route))
    end
  end
end
