defmodule PkiRaPortalWeb.E2ETest do
  @moduledoc """
  End-to-end tests simulating a complete user journey through multiple
  LiveView pages in the RA Portal.
  """
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @csr1_id "019577b0-0010-7000-8000-000000000010"

  describe "RA admin full journey" do
    @admin %{id: 1, username: "raadmin1", role: "ra_admin"}

    setup %{conn: conn} do
      conn = init_test_session(conn, %{current_user: @admin})
      {:ok, conn: conn}
    end

    test "admin: dashboard -> create user -> create profile -> create API key -> logout", %{conn: conn} do
      # Step 1: Visit dashboard and verify it renders
      {:ok, _view, html} = live(conn, "/")
      assert html =~ "Dashboard"
      assert html =~ "RA Overview"

      # Step 2: Navigate to users and create an ra_officer
      {:ok, users_view, html} = live(conn, "/users")
      assert html =~ "User Management"

      html =
        users_view
        |> form("#create-user-form form", %{
          username: "e2e_officer",
          display_name: "E2E Officer",
          role: "ra_officer"
        })
        |> render_submit()

      assert html =~ "e2e_officer"
      assert html =~ "E2E Officer"

      # Step 3: Navigate to cert profiles and create a profile
      {:ok, profiles_view, html} = live(conn, "/cert-profiles")
      assert html =~ "Certificate Profiles"

      html =
        profiles_view
        |> form("#create-profile-form form", %{
          name: "E2E Code Signing",
          key_usage: "digitalSignature",
          ext_key_usage: "codeSigning",
          digest_algo: "SHA-256",
          validity_days: "365"
        })
        |> render_submit()

      assert html =~ "E2E Code Signing"

      # Step 4: Navigate to API keys and create a key
      {:ok, keys_view, html} = live(conn, "/api-keys")
      assert html =~ "API Key Management"

      html =
        keys_view
        |> form("#create-api-key-form form", %{name: "E2E Test Key"})
        |> render_submit()

      # Verify the raw key is shown (one-time display)
      assert html =~ "New API Key Created"
      assert has_element?(keys_view, "#raw-key-value")

      # Step 5: Logout
      conn = delete(conn, ~p"/logout")
      assert redirected_to(conn) == "/login"

      # After logout, accessing / should redirect to login
      conn = get(recycle(conn), ~p"/")
      assert redirected_to(conn) == "/login"
    end
  end

  describe "RA officer CSR workflow" do
    @officer %{id: 2, username: "raofficer1", role: "ra_officer"}

    setup %{conn: conn} do
      conn = init_test_session(conn, %{current_user: @officer})
      {:ok, conn: conn}
    end

    test "officer: dashboard -> CSR list -> view CSR -> approve -> dashboard stats", %{conn: conn} do
      # Step 1: Visit dashboard
      {:ok, _view, html} = live(conn, "/")
      assert html =~ "Dashboard"
      assert html =~ "Pending CSRs"

      # Step 2: Navigate to CSRs and verify list shows pending CSRs
      {:ok, csrs_view, html} = live(conn, "/csrs")
      assert html =~ "CSR Management"
      assert html =~ "pending"
      assert html =~ "CN=example.com"

      # Step 3: View CSR detail
      html =
        csrs_view
        |> element("#csr-#{@csr1_id} button", "View")
        |> render_click()

      assert html =~ "CSR Detail"
      assert html =~ "Public Key Algorithm"

      # Step 4: Close the detail panel
      html = csrs_view |> element("button", "Close") |> render_click()
      refute html =~ "CSR Detail"

      # Step 5: Approve the CSR
      html =
        csrs_view
        |> element("#csr-#{@csr1_id} button", "Approve")
        |> render_click()

      assert html =~ "CSR Management"

      # Step 6: Navigate back to dashboard and verify it still renders
      {:ok, _view, html} = live(conn, "/")
      assert html =~ "Dashboard"
      assert html =~ "Pending CSRs"
    end

    test "officer: view and reject a CSR with reason", %{conn: conn} do
      {:ok, csrs_view, _html} = live(conn, "/csrs")

      # Open CSR detail
      csrs_view |> element("#csr-#{@csr1_id} button", "View") |> render_click()

      # Reject with a reason
      html =
        csrs_view
        |> form("#reject-form", %{csr_id: @csr1_id, reason: "Key too weak for policy"})
        |> render_submit()

      # After rejection, detail is closed and list refreshed
      assert html =~ "CSR Management"
      refute html =~ "CSR Detail"
    end
  end

  describe "authentication boundary" do
    test "unauthenticated user is redirected to login for all pages", %{conn: conn} do
      for path <- ["/", "/users", "/csrs", "/cert-profiles", "/api-keys", "/service-configs"] do
        assert {:error, {:redirect, %{to: "/login"}}} = live(conn, path),
               "Expected redirect to /login for path #{path}"
      end
    end
  end
end
