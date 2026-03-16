defmodule PkiCaPortalWeb.PageControllerTest do
  use PkiCaPortalWeb.ConnCase

  test "GET / redirects to login when not authenticated", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert redirected_to(conn) == "/login"
  end

  test "GET / renders home page when authenticated", %{conn: conn} do
    user = %{did: "did:ssdid:admin1", role: "ca_admin", ca_instance_id: 1}

    conn =
      conn
      |> init_test_session(%{current_user: user})
      |> get(~p"/")

    assert html_response(conn, 200) =~ "Dashboard"
  end
end
