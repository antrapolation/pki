defmodule PkiRaPortalWeb.ErrorPathsTest do
  @moduledoc """
  Tests for error branches in LiveView handle_event callbacks.

  Temporarily swaps the RA engine client to an error-returning mock
  to exercise the {:error, reason} branches. Verifies that the LiveView
  handles errors gracefully without crashing and preserves existing state.
  """
  use PkiRaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  @user %{did: "did:ssdid:raadmin1", role: "ra_admin"}

  setup %{conn: conn} do
    conn = init_test_session(conn, %{current_user: @user})
    original = Application.get_env(:pki_ra_portal, :ra_engine_client)

    on_exit(fn ->
      Application.put_env(:pki_ra_portal, :ra_engine_client, original)
    end)

    {:ok, conn: conn}
  end

  describe "CsrsLive error paths" do
    test "approve_csr error does not crash and preserves state", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/csrs")

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> element("#csr-1 button", "Approve")
        |> render_click()

      # View still works, CSR list preserved
      assert html =~ "CSR Management"
      assert html =~ "CN=example.com"
    end

    test "reject_csr error does not crash and preserves state", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/csrs")

      # Open detail first to access reject form
      view |> element("#csr-1 button", "View") |> render_click()

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> form("#reject-form", %{csr_id: "1", reason: "Bad request"})
        |> render_submit()

      # View still works
      assert html =~ "CSR Management"
    end
  end

  describe "UsersLive error paths" do
    test "create_user error does not crash and preserves user list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> form("#create-user-form form", %{
          did: "did:ssdid:fail",
          display_name: "Fail User",
          role: "ra_officer"
        })
        |> render_submit()

      # View still works, existing users preserved, failed user not added
      assert html =~ "User Management"
      assert html =~ "RA Admin One"
      refute html =~ "Fail User"
    end

    test "delete_user error does not crash and preserves user list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> element("#user-1 button", "Suspend")
        |> render_click()

      # View still works, user not removed
      assert html =~ "User Management"
      assert html =~ "RA Admin One"
    end
  end

  describe "CertProfilesLive error paths" do
    test "create_profile error does not crash and preserves list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/cert-profiles")

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> form("#create-profile-form form", %{
          name: "Fail Profile",
          key_usage: "digitalSignature",
          ext_key_usage: "serverAuth",
          digest_algo: "SHA-256",
          validity_days: "365"
        })
        |> render_submit()

      # View still works, failed profile not added
      assert html =~ "Certificate Profiles"
      assert html =~ "TLS Server"
      refute html =~ "Fail Profile"
    end

    test "delete_profile error does not crash and preserves list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/cert-profiles")

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> element("#profile-1 button", "Delete")
        |> render_click()

      # View still works, profile not removed
      assert html =~ "Certificate Profiles"
      assert html =~ "TLS Server"
    end
  end

  describe "ServiceConfigsLive error path" do
    test "configure_service error does not crash and preserves list", %{conn: conn} do
      {:ok, view, html_before} = live(conn, "/service-configs")

      initial_count = length(Regex.scan(~r/<tr id="config-/, html_before))

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> form("#configure-service-form form", %{
          service_type: "TSA",
          port: "9090",
          url: "http://tsa.example.com",
          rate_limit: "500",
          ip_whitelist: "",
          ip_blacklist: ""
        })
        |> render_submit()

      # View still works, no new config added
      assert html =~ "Service Configuration"
      new_count = length(Regex.scan(~r/<tr id="config-/, html))
      assert new_count == initial_count
    end
  end

  describe "ApiKeysLive error paths" do
    test "create_api_key error does not crash and preserves list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/api-keys")

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> form("#create-api-key-form form", %{name: "Fail Key"})
        |> render_submit()

      # View still works, no raw key shown
      assert html =~ "API Key Management"
      refute html =~ "New API Key Created"
    end

    test "revoke_api_key error does not crash and preserves list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/api-keys")

      Application.put_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.ErrorMock)

      html =
        view
        |> element("#api-key-1 button", "Revoke")
        |> render_click()

      # View still works
      assert html =~ "API Key Management"
      assert html =~ "Production API Key"
    end
  end
end
