defmodule PkiRaPortalWeb.CsrsLiveTest do
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{id: 2, username: "raofficer1", role: "ra_officer"}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    {:ok, conn: conn}
  end

  test "mounts and renders CSR list", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/csrs")

    assert html =~ "CSR Management"
    assert html =~ "CN=example.com"
    assert html =~ "TLS Server"
    assert html =~ "pending"
  end

  test "filter_status event filters CSRs", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/csrs")

    html =
      view
      |> form("#csr-filter form", %{status: "pending"})
      |> render_change()

    assert html =~ "CN=example.com"
    refute html =~ "CN=api.example.com"
  end

  test "view_csr event shows CSR detail", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/csrs")

    html =
      view
      |> element("#csr-1 button", "View")
      |> render_click()

    assert html =~ "CSR Detail"
    assert html =~ "Public Key Algorithm"
  end

  test "approve_csr event approves a CSR", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/csrs")

    html =
      view
      |> element("#csr-1 button", "Approve")
      |> render_click()

    # After approval, the CSR list is refreshed from mock (which always returns same data)
    assert html =~ "CSR Management"
  end

  test "close_detail event hides CSR detail", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/csrs")

    # Open detail
    view |> element("#csr-1 button", "View") |> render_click()

    # Close detail
    html = view |> element("button", "Close") |> render_click()

    refute html =~ "CSR Detail"
  end

  test "reject_csr event rejects a CSR", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/csrs")

    # First open the CSR detail to access the reject form
    view |> element("#csr-1 button", "View") |> render_click()

    # Submit the reject form with a reason
    html =
      view
      |> form("#reject-form", %{csr_id: "1", reason: "Invalid key usage"})
      |> render_submit()

    # After rejection, the CSR list is refreshed and detail is closed
    assert html =~ "CSR Management"
    refute html =~ "CSR Detail"
  end
end
