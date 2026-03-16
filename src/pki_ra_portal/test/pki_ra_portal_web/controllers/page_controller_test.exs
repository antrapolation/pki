defmodule PkiRaPortalWeb.PageControllerTest do
  use PkiRaPortalWeb.ConnCase

  test "GET / redirects to login when not authenticated", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert redirected_to(conn) == "/login"
  end
end
