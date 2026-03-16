defmodule PkiCaPortalWeb.CeremonyLiveTest do
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{did: "did:ssdid:admin1", role: "ca_admin", ca_instance_id: 1}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders ceremony list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/ceremony")

    assert html =~ "Key Ceremony"
    assert html =~ "ML-DSA-65"
    assert html =~ "completed"
    assert html =~ "Initiate Ceremony"
  end

  test "initiate_ceremony event works", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/ceremony")

    view
    |> form("#initiate-ceremony-form form", %{
      algorithm: "ML-DSA-65",
      keystore_id: "1",
      threshold_k: "2",
      threshold_n: "3",
      domain_info: "test domain"
    })
    |> render_submit()

    assert has_element?(view, "#ceremony-status")
    assert has_element?(view, "#ceremony-state", "initiated")
    assert render(view) =~ "ML-DSA-65"
  end
end
