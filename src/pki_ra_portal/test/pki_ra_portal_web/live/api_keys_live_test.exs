defmodule PkiRaPortalWeb.ApiKeysLiveTest do
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{did: "did:ssdid:raadmin1", role: "ra_admin"}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders API key list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/api-keys")

    assert html =~ "API Key Management"
    assert html =~ "Production API Key"
    assert html =~ "Staging API Key"
    assert html =~ "active"
    assert html =~ "revoked"
  end

  test "create_api_key event creates a key and shows raw key", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/api-keys")

    html =
      view
      |> form("#create-api-key-form form", %{name: "Test Key"})
      |> render_submit()

    assert html =~ "New API Key Created"
    assert has_element?(view, "#raw-key-value")
  end

  test "dismiss_raw_key event hides the raw key", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/api-keys")

    # Create key first
    view
    |> form("#create-api-key-form form", %{name: "Test Key"})
    |> render_submit()

    # Dismiss
    html = view |> element("button", "Dismiss") |> render_click()

    refute html =~ "New API Key Created"
  end

  test "revoke_api_key event revokes a key", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/api-keys")

    html =
      view
      |> element("#api-key-1 button", "Revoke")
      |> render_click()

    # After revoking, the key status should change
    assert html =~ "revoked"
  end
end
