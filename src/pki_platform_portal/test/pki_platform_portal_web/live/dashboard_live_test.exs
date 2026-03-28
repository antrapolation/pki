defmodule PkiPlatformPortalWeb.DashboardLiveTest do
  use PkiPlatformPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{"username" => "admin", "display_name" => "Platform Admin", "role" => "platform_admin"}

  describe "authenticated" do
    setup %{conn: conn} do
      conn = init_test_session(conn, %{current_user: @user})
      {:ok, conn: conn}
    end

    test "mounts and renders dashboard with tenant counts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "Dashboard"
      assert html =~ "Total Tenants"
      assert html =~ "Active Tenants"
    end

    test "renders stat cards", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      assert has_element?(view, "#total-tenants-card")
      assert has_element?(view, "#active-tenants-card")
      assert has_element?(view, "#dashboard")
    end

    test "renders recent tenants section", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      assert has_element?(view, "#recent-tenants")
    end

    test "shows manage tenants link", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ ~s(href="/tenants")
      assert html =~ "Manage Tenants"
    end
  end

  test "redirects to login when not authenticated", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/")
  end
end
