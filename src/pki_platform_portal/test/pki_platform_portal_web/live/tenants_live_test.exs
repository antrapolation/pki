defmodule PkiPlatformPortalWeb.TenantsLiveTest do
  use PkiPlatformPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{"username" => "admin", "display_name" => "Platform Admin", "role" => "platform_admin"}

  describe "authenticated" do
    setup %{conn: conn} do
      conn = init_test_session(conn, %{current_user: @user})
      {:ok, conn: conn}
    end

    test "mounts and renders tenants page", %{conn: conn} do
      {:ok, view, html} = live(conn, "/tenants")

      assert html =~ "Tenants"
      assert html =~ "All Tenants"
      assert has_element?(view, "#tenants-page")
    end

    test "renders create tenant form", %{conn: conn} do
      {:ok, view, html} = live(conn, "/tenants")

      assert html =~ "Create New Tenant"
      assert has_element?(view, "#create-tenant-form")
      assert has_element?(view, "#tenant-name")
      assert has_element?(view, "#tenant-slug")
    end

    test "renders tenant list table", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/tenants")

      assert has_element?(view, "#tenant-list")
    end

    test "shows empty state when no tenants", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/tenants")

      assert html =~ "No tenants yet"
    end
  end

  test "redirects to login when not authenticated", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/tenants")
  end
end
