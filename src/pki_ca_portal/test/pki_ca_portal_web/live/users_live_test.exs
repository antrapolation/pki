defmodule PkiCaPortalWeb.UsersLiveTest do
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 1, username: "admin1", role: "ca_admin", ca_instance_id: 1}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders user list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/users")

    assert html =~ "User Management"
    assert html =~ "admin1"
    assert html =~ "Admin One"
    assert html =~ "keymgr1"
    assert html =~ "Key Manager One"
  end

  test "create_user event adds a user", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/users")

    html =
      view
      |> form("#create-user-form form", %{
        username: "newuser1",
        display_name: "New User",
        role: "auditor"
      })
      |> render_submit()

    assert html =~ "newuser1"
    assert html =~ "New User"
  end

  test "filter_role event filters users", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/users")

    html =
      view
      |> form("#user-filter form", %{role: "key_manager"})
      |> render_change()

    assert html =~ "Key Manager One"
    refute html =~ "Admin One"
  end
end
