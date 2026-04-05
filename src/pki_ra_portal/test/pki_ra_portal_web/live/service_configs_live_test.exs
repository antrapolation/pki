defmodule PkiRaPortalWeb.ServiceConfigsLiveTest do
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 1, username: "raadmin1", role: "ra_admin"}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders service config list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/service-configs")

    assert html =~ "Validation Endpoints"
    assert html =~ "OCSP Responder"
    assert html =~ "CRL Distribution"
    assert html =~ "8080"
  end

  test "configure_service event adds a config", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/service-configs")

    html =
      view
      |> form("#configure-service-form form", %{
        service_type: "TSA",
        port: "9090",
        url: "http://tsa.example.com",
        rate_limit: "500",
        ip_whitelist: "10.0.0.0/8",
        ip_blacklist: ""
      })
      |> render_submit()

    # The new service should appear in the table
    assert html =~ "TSA"
    assert html =~ "http://tsa.example.com"
  end
end
