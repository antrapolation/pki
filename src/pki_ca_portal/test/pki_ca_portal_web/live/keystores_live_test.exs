defmodule PkiCaPortalWeb.KeystoresLiveTest do
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 1, username: "admin1", role: "ca_admin", ca_instance_id: 1}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders keystore list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/keystores")

    assert html =~ "Keystore Management"
    assert html =~ "software"
    assert html =~ "hsm"
    assert html =~ "StrapSoftPrivKeyStoreProvider"
    assert html =~ "StrapSofthsmPrivKeyStoreProvider"
  end

  test "configure_keystore event adds a keystore", %{conn: conn} do
    {:ok, view, html} = live(conn, "/keystores")

    # Count initial keystores
    initial_count = length(Regex.scan(~r/<tr id="keystore-/, html))

    view
    |> form("#configure-keystore-form form", %{type: "software"})
    |> render_submit()

    rendered = render(view)
    new_count = length(Regex.scan(~r/<tr id="keystore-/, rendered))
    assert new_count == initial_count + 1
  end
end
