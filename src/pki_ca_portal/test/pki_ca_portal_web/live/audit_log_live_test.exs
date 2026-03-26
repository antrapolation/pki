defmodule PkiCaPortalWeb.AuditLogLiveTest do
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 1, username: "admin1", role: "ca_admin", ca_instance_id: 1}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders event list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/audit-log")

    assert html =~ "Audit Log"
    assert html =~ "login"
    assert html =~ "key_generated"
    assert html =~ "admin1"
    assert html =~ "keymgr1"
  end

  test "filter event applies filters", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/audit-log")

    html =
      view
      |> form("#audit-filter form", %{
        action: "login",
        actor: "admin1",
        date_from: "",
        date_to: ""
      })
      |> render_submit()

    assert html =~ "login"
  end
end
