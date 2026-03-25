defmodule PkiRaPortalWeb.CertProfilesLiveTest do
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 1, username: "raadmin1", role: "ra_admin"}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders cert profile list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/cert-profiles")

    assert html =~ "Certificate Profiles"
    assert html =~ "TLS Server"
    assert html =~ "Client Auth"
    assert html =~ "SHA-256"
  end

  test "create_profile event adds a profile", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/cert-profiles")

    html =
      view
      |> form("#create-profile-form form", %{
        name: "Code Signing",
        key_usage: "digitalSignature",
        ext_key_usage: "codeSigning",
        digest_algo: "SHA-256",
        validity_days: "180"
      })
      |> render_submit()

    assert html =~ "Code Signing"
  end

  test "edit_profile event shows edit form", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/cert-profiles")

    html =
      view
      |> element("#profile-1 button", "Edit")
      |> render_click()

    assert html =~ "Edit Profile"
  end

  test "delete_profile event removes a profile", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/cert-profiles")

    html =
      view
      |> element("#profile-1 button", "Delete")
      |> render_click()

    refute html =~ "profile-1"
  end
end
