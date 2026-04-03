defmodule PkiCaPortalWeb.CertificatesLiveTest do
  @moduledoc """
  Integration tests for the Certificates Management page.

  Verifies:
  - RBAC access control (ca_admin and key_manager can access, auditor cannot)
  - Page rendering (description banner, filter controls, table headers, empty state)
  - Issuer key search interaction
  - Status filter interaction
  - Revocation controls visibility by role

  Note: The Mock client returns empty lists for certificate and issuer key queries,
  so these tests verify page structure and event handling, not data rendering.
  """
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  alias PkiCaPortal.SessionStore

  @admin %{
    user_id: "admin-001",
    username: "test-ca-admin",
    role: "ca_admin",
    tenant_id: "tenant-001",
    display_name: "Test CA Admin",
    email: "admin@test.com",
    ca_instance_id: "ca-001",
    ip: "127.0.0.1",
    user_agent: "TestAgent/1.0"
  }

  @key_manager %{
    user_id: "km-001",
    username: "test-km",
    role: "key_manager",
    tenant_id: "tenant-001",
    display_name: "Key Manager",
    email: "km@test.com",
    ca_instance_id: "ca-001",
    ip: "127.0.0.1",
    user_agent: "TestAgent/1.0"
  }

  @auditor %{
    user_id: "auditor-001",
    username: "test-auditor",
    role: "auditor",
    tenant_id: "tenant-001",
    display_name: "Auditor",
    email: "auditor@test.com",
    ip: "127.0.0.1",
    user_agent: "TestAgent/1.0"
  }

  setup do
    SessionStore.clear_all()
    :ok
  end

  defp login_as(user) do
    {:ok, session_id} = SessionStore.create(user)

    conn =
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
      |> init_test_session(%{session_id: session_id})

    {conn, session_id}
  end

  # ---------------------------------------------------------------------------
  # RBAC access control
  # ---------------------------------------------------------------------------

  describe "access control" do
    test "ca_admin can access certificates page" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/certificates")
      assert html =~ "Issued Certificates"
    end

    test "key_manager can access certificates page" do
      {conn, _} = login_as(@key_manager)
      {:ok, _view, html} = live(conn, "/certificates")
      assert html =~ "Issued Certificates"
    end

    test "auditor cannot access certificates page" do
      {conn, _} = login_as(@auditor)
      assert {:error, {:redirect, %{to: "/"}}} = live(conn, "/certificates")
    end

    test "unauthenticated user is redirected to login", %{conn: conn} do
      assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/certificates")
    end
  end

  # ---------------------------------------------------------------------------
  # Page rendering
  # ---------------------------------------------------------------------------

  describe "page rendering" do
    test "shows description banner" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/certificates")
      assert html =~ "Issued Certificates"
      assert html =~ "View and manage certificates"
    end

    test "shows filter controls" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/certificates")
      assert html =~ "CA Instance"
      assert html =~ "Issuer Key"
      assert html =~ "Status"
    end

    test "shows table headers" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/certificates")
      assert html =~ "Serial"
      assert html =~ "Subject DN"
      assert html =~ "Status"
    end

    test "shows loading state on initial render then empty state" do
      {conn, _} = login_as(@admin)
      {:ok, view, html} = live(conn, "/certificates")
      # Static render shows loading; after connected mount loads data, shows empty
      assert html =~ "Loading..."
      # After the :load_data message is processed, re-render shows empty state
      html = render(view)
      assert html =~ "No certificates found"
    end

    test "sets correct page title" do
      {conn, _} = login_as(@admin)
      {:ok, view, _html} = live(conn, "/certificates")
      assert render(view) =~ "Certificates"
    end
  end

  # ---------------------------------------------------------------------------
  # Issuer key search
  # ---------------------------------------------------------------------------

  describe "issuer key search" do
    test "search input is present" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/certificates")
      assert html =~ "Search key alias or algorithm"
    end

    test "typing in search triggers filter event without crash" do
      {conn, _} = login_as(@admin)
      {:ok, view, _html} = live(conn, "/certificates")

      # Fire keyup event — mock returns no keys so no search results
      html = render_keyup(view, "search_issuer_key", %{"value" => "root"})

      # Page should still render normally
      assert html =~ "Search key alias or algorithm"
    end
  end

  # ---------------------------------------------------------------------------
  # Status filter
  # ---------------------------------------------------------------------------

  describe "status filter" do
    test "can filter by active status" do
      {conn, _} = login_as(@admin)
      {:ok, view, _html} = live(conn, "/certificates")

      html =
        view
        |> element("select[name=status]")
        |> render_change(%{"status" => "active"})

      assert html =~ "No certificates found"
    end

    test "can filter by revoked status" do
      {conn, _} = login_as(@admin)
      {:ok, view, _html} = live(conn, "/certificates")

      html =
        view
        |> element("select[name=status]")
        |> render_change(%{"status" => "revoked"})

      assert html =~ "No certificates found"
    end
  end

  # ---------------------------------------------------------------------------
  # Revocation controls visibility
  # ---------------------------------------------------------------------------

  describe "revocation controls" do
    test "no revoke section when no certificate selected (ca_admin)" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/certificates")
      # No cert selected so detail panel is not rendered
      refute html =~ "Revoke Certificate"
    end

    test "no revoke section when no certificate selected (key_manager)" do
      {conn, _} = login_as(@key_manager)
      {:ok, _view, html} = live(conn, "/certificates")
      refute html =~ "Revoke Certificate"
    end
  end
end
