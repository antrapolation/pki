defmodule PkiCaPortalWeb.DashboardLiveTest do
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 1, username: "admin1", role: "ca_admin", ca_instance_id: 1}

  describe "authenticated" do
    setup %{conn: conn} do
      conn = init_test_session(conn, %{current_user: @user})
      {:ok, conn: conn}
    end

    test "mounts and renders dashboard", %{conn: conn} do
      {:ok, view, html} = live(conn, "/")

      assert html =~ "Dashboard"
      assert html =~ "Engine Status"
      assert has_element?(view, "#status-card")
      assert has_element?(view, "#key-summary")
      assert has_element?(view, "#recent-ceremonies")
      assert has_element?(view, "#quick-actions")
    end

    test "displays engine status", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "running"
    end

    test "displays recent ceremonies", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "ML-DSA-65"
      assert html =~ "completed"
    end

    test "displays quick action links", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ ~s(href="/ceremony")
      assert html =~ ~s(href="/users")
      assert html =~ ~s(href="/keystores")
      assert html =~ ~s(href="/audit-log")
    end
  end

  test "redirects to login when not authenticated", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/")
  end
end
