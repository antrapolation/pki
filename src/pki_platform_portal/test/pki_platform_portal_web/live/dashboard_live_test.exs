defmodule PkiPlatformPortalWeb.DashboardLiveTest do
  use PkiPlatformPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  setup %{conn: conn} do
    PkiPlatformPortal.SessionStore.clear_all()
    %{conn: conn} = log_in_as_super_admin(conn)
    {:ok, conn: conn}
  end

  describe "authenticated" do
    test "mounts /", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      assert has_element?(view, "#dashboard")
      assert render(view) =~ "Total Tenants"
      assert render(view) =~ "Active"
    end

    test "shows zeroed tenant counts when no tenants exist", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      html = render(view)
      # Both "Total Tenants" and "Active" cards should show 0 initially.
      assert html =~ "Total Tenants"
      assert html =~ ~r|<p class="text-xl font-bold">0</p>|
    end

    test "links to /tenants", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      assert html =~ ~s(href="/tenants")
    end
  end

  test "redirects to /login when unauthenticated" do
    conn = Phoenix.ConnTest.build_conn() |> Plug.Test.init_test_session(%{})
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/")
  end
end
