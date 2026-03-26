defmodule PkiCaPortalWeb.Live.IntegrationTest do
  @moduledoc """
  Layer 2 integration tests: Portal -> Engine.

  Uses the StatefulMock client to verify the full round-trip:
  LiveView render -> user action -> CaEngineClient call -> state change -> re-render.

  Unlike unit tests (which use the static Mock), these tests verify that:
  1. Created entities appear in subsequent list views
  2. User actions produce cumulative state changes
  3. The client interface contract is exercised with stateful data
  """

  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  alias PkiCaPortal.CaEngineClient.StatefulMock

  @user %{"id" => 1, "username" => "admin1", "role" => "ca_admin", "ca_instance_id" => 1}

  setup %{conn: conn} do
    # Start the StatefulMock Agent and configure it as the client
    {:ok, _pid} = StatefulMock.start_link()
    Application.put_env(:pki_ca_portal, :ca_engine_client, StatefulMock)

    conn = init_test_session(conn, %{current_user: @user})

    on_exit(fn ->
      Application.put_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock)
    end)

    {:ok, conn: conn}
  end

  # -- Users page integration --

  describe "users page integration" do
    test "starts with empty user list", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/users")

      assert html =~ "User Management"
      # StatefulMock starts empty -- no pre-seeded users
      refute html =~ "admin1"
    end

    test "create user -> user appears in list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      html =
        view
        |> form("#create-user-form form", %{
          username: "integration1",
          display_name: "Integration User",
          role: "ca_admin"
        })
        |> render_submit()

      assert html =~ "integration1"
      assert html =~ "Integration User"
    end

    test "create multiple users -> all appear in list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      # Create first user
      view
      |> form("#create-user-form form", %{
        username: "user_a",
        display_name: "User A",
        role: "ca_admin"
      })
      |> render_submit()

      # Create second user
      html =
        view
        |> form("#create-user-form form", %{
          username: "user_b",
          display_name: "User B",
          role: "key_manager"
        })
        |> render_submit()

      assert html =~ "user_a"
      assert html =~ "User A"
      assert html =~ "user_b"
      assert html =~ "User B"
    end

    test "create user then delete -> user removed from list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      # Create a user
      view
      |> form("#create-user-form form", %{
        username: "deleteme",
        display_name: "Delete Me",
        role: "auditor"
      })
      |> render_submit()

      rendered = render(view)
      assert rendered =~ "deleteme"

      # Find the user row and click delete
      view
      |> element("button[phx-click=delete_user]")
      |> render_click()

      rendered = render(view)
      refute rendered =~ "deleteme"
    end

    test "create users and filter by role", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/users")

      # Create an admin
      view
      |> form("#create-user-form form", %{
        username: "admin_filter",
        display_name: "Admin Filter",
        role: "ca_admin"
      })
      |> render_submit()

      # Create a key manager
      view
      |> form("#create-user-form form", %{
        username: "keymgr_filter",
        display_name: "KeyMgr Filter",
        role: "key_manager"
      })
      |> render_submit()

      # Filter by key_manager
      html =
        view
        |> form("#user-filter form", %{role: "key_manager"})
        |> render_change()

      assert html =~ "KeyMgr Filter"
      refute html =~ "Admin Filter"

      # Filter by all
      html =
        view
        |> form("#user-filter form", %{role: "all"})
        |> render_change()

      assert html =~ "Admin Filter"
      assert html =~ "KeyMgr Filter"
    end
  end

  # -- Keystores page integration --

  describe "keystores page integration" do
    test "starts with empty keystore list", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/keystores")

      assert html =~ "Keystore Management"
      # No pre-seeded keystores in StatefulMock
      refute html =~ "StrapSoftPrivKeyStoreProvider"
    end

    test "configure keystore -> keystore appears in list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/keystores")

      html =
        view
        |> form("#configure-keystore-form form", %{type: "software"})
        |> render_submit()

      assert html =~ "software"
      assert html =~ "StrapSoftPrivKeyStoreProvider"
    end

    test "configure multiple keystores -> all appear", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/keystores")

      view
      |> form("#configure-keystore-form form", %{type: "software"})
      |> render_submit()

      html =
        view
        |> form("#configure-keystore-form form", %{type: "hsm"})
        |> render_submit()

      assert html =~ "software"
      assert html =~ "hsm"
      assert html =~ "StrapSoftPrivKeyStoreProvider"
      assert html =~ "StrapSofthsmPrivKeyStoreProvider"
    end
  end

  # -- Ceremony page integration --

  describe "ceremony page integration" do
    test "starts with empty ceremony list", %{conn: conn} do
      # We need at least one keystore for the ceremony form dropdown
      StatefulMock.configure_keystore(1, %{type: "software"})

      {:ok, _view, html} = live(conn, "/ceremony")

      assert html =~ "Key Ceremony"
      assert html =~ "Initiate Key Ceremony"
    end

    test "initiate ceremony -> ceremony status shown", %{conn: conn} do
      # Pre-configure a keystore so the ceremony form has options
      {:ok, keystore} = StatefulMock.configure_keystore(1, %{type: "software"})

      {:ok, view, _html} = live(conn, "/ceremony")

      view
      |> form("#initiate-ceremony-form form", %{
        algorithm: "ML-DSA-65",
        keystore_id: to_string(keystore.id),
        threshold_k: "2",
        threshold_n: "3",
        domain_info: "integration test domain"
      })
      |> render_submit()

      assert has_element?(view, "#ceremony-status")
      assert has_element?(view, "#ceremony-state", "initiated")
      assert render(view) =~ "ML-DSA-65"
    end

    test "initiate ceremony -> ceremony appears in past ceremonies table", %{conn: conn} do
      {:ok, keystore} = StatefulMock.configure_keystore(1, %{type: "software"})

      {:ok, view, _html} = live(conn, "/ceremony")

      view
      |> form("#initiate-ceremony-form form", %{
        algorithm: "KAZ-SIGN-256",
        keystore_id: to_string(keystore.id),
        threshold_k: "2",
        threshold_n: "3",
        domain_info: "test"
      })
      |> render_submit()

      rendered = render(view)
      # The ceremony should appear in the past ceremonies table
      assert rendered =~ "KAZ-SIGN-256"
      assert rendered =~ "initiated"
    end
  end

  # -- Audit log page integration --

  describe "audit log page integration" do
    test "starts with empty audit log", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/audit-log")

      assert html =~ "Audit Log"
    end

    test "actions generate audit events that appear in log", %{conn: conn} do
      # Perform some actions that generate audit events
      StatefulMock.create_user(1, %{username: "audited_user", display_name: "Audited", role: "ca_admin"})
      StatefulMock.configure_keystore(1, %{type: "software"})

      {:ok, _view, html} = live(conn, "/audit-log")

      assert html =~ "user_created"
      assert html =~ "keystore_configured"
    end

    test "cross-page integration: create user on users page then see event in audit log", %{conn: conn} do
      # First, create a user via the users page
      {:ok, view, _html} = live(conn, "/users")

      view
      |> form("#create-user-form form", %{
        username: "cross_page",
        display_name: "Cross Page User",
        role: "ca_admin"
      })
      |> render_submit()

      # Now navigate to audit log and verify the event
      {:ok, _view, html} = live(conn, "/audit-log")
      assert html =~ "user_created"
      assert html =~ "cross_page"
    end
  end

  # -- Full workflow integration --

  describe "full workflow integration" do
    test "complete CA setup flow: users -> keystores -> ceremony -> audit trail", %{conn: conn} do
      # Step 1: Create users
      {:ok, users_view, _html} = live(conn, "/users")

      users_view
      |> form("#create-user-form form", %{
        username: "full_admin",
        display_name: "Full Admin",
        role: "ca_admin"
      })
      |> render_submit()

      users_view
      |> form("#create-user-form form", %{
        username: "full_keymgr",
        display_name: "Full KeyMgr",
        role: "key_manager"
      })
      |> render_submit()

      rendered = render(users_view)
      assert rendered =~ "Full Admin"
      assert rendered =~ "Full KeyMgr"

      # Step 2: Configure keystore
      {:ok, ks_view, _html} = live(conn, "/keystores")

      ks_view
      |> form("#configure-keystore-form form", %{type: "software"})
      |> render_submit()

      rendered = render(ks_view)
      assert rendered =~ "software"

      # Step 3: Initiate ceremony
      {:ok, ceremony_view, _html} = live(conn, "/ceremony")

      # Get keystore id from state
      {:ok, keystores} = StatefulMock.list_keystores(1)
      ks = hd(keystores)

      ceremony_view
      |> form("#initiate-ceremony-form form", %{
        algorithm: "ML-DSA-65",
        keystore_id: to_string(ks.id),
        threshold_k: "2",
        threshold_n: "3",
        domain_info: "full workflow test"
      })
      |> render_submit()

      assert has_element?(ceremony_view, "#ceremony-state", "initiated")

      # Step 4: Verify audit trail captures all actions
      {:ok, _audit_view, html} = live(conn, "/audit-log")
      assert html =~ "user_created"
      assert html =~ "keystore_configured"
      assert html =~ "ceremony_initiated"
    end
  end
end
