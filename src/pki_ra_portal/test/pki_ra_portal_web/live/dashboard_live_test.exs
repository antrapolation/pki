defmodule PkiRaPortalWeb.DashboardLiveTest do
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{did: "did:ssdid:raadmin1", role: "ra_admin"}

  describe "authenticated" do
    setup %{conn: conn} do
      conn = init_test_session(conn, %{current_user: @user})
      {:ok, conn: conn}
    end

    test "mounts and renders dashboard", %{conn: conn} do
      {:ok, view, html} = live(conn, "/")

      assert html =~ "Dashboard"
      assert html =~ "RA Overview"
      assert has_element?(view, "#status-card")
      assert has_element?(view, "#recent-csrs")
      assert has_element?(view, "#quick-actions")
    end

    test "displays pending CSR count", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "Pending CSRs"
    end

    test "displays recent CSRs", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "CN=example.com"
      assert html =~ "pending"
    end

    test "displays quick action links", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ ~s(href="/csrs")
      assert html =~ ~s(href="/users")
      assert html =~ ~s(href="/cert-profiles")
      assert html =~ ~s(href="/service-configs")
      assert html =~ ~s(href="/api-keys")
    end
  end

  test "redirects to login when not authenticated", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/")
  end
end
