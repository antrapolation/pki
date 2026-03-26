defmodule PkiRaPortalWeb.UsersLiveTest do
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 1, username: "raadmin1", role: "ra_admin"}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders user list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/users")

    assert html =~ "User Management"
    assert html =~ "raadmin1"
    assert html =~ "RA Admin One"
    assert html =~ "raofficer1"
    assert html =~ "RA Officer One"
  end

  test "create_user event adds a user", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/users")

    html =
      view
      |> form("#create-user-form form", %{
        username: "newuser1",
        display_name: "New User",
        role: "ra_officer"
      })
      |> render_submit()

    assert html =~ "newuser1"
    assert html =~ "New User"
  end

  test "filter_role event filters users", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/users")

    html =
      view
      |> form("#user-filter form", %{role: "ra_officer"})
      |> render_change()

    assert html =~ "RA Officer One"
    refute html =~ "RA Admin One"
  end
end
