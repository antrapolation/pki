defmodule PkiCaPortalWeb.E2ETest do
  @moduledoc """
  End-to-end tests simulating a complete user journey through multiple
  LiveView pages in the CA Portal.
  """
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  describe "CA admin full journey" do
    @admin %{did: "did:ssdid:admin1", role: "ca_admin", ca_instance_id: 1}

    setup %{conn: conn} do
      conn = init_test_session(conn, %{current_user: @admin})
      {:ok, conn: conn}
    end

    test "admin: dashboard -> create user -> configure keystore -> initiate ceremony -> audit log", %{conn: conn} do
      # Step 1: Visit dashboard and verify engine status
      {:ok, view, html} = live(conn, "/")
      assert html =~ "Dashboard"
      assert html =~ "Engine Status"
      assert html =~ "running"
      assert has_element?(view, "#status-card")
      assert has_element?(view, "#key-summary")
      assert has_element?(view, "#recent-ceremonies")

      # Step 2: Navigate to users and create a key_manager
      {:ok, users_view, html} = live(conn, "/users")
      assert html =~ "User Management"
      assert html =~ "Admin One"
      assert html =~ "Key Manager One"

      html =
        users_view
        |> form("#create-user-form form", %{
          did: "did:ssdid:e2e_keymgr",
          display_name: "E2E Key Manager",
          role: "key_manager"
        })
        |> render_submit()

      assert html =~ "did:ssdid:e2e_keymgr"
      assert html =~ "E2E Key Manager"

      # Step 3: Navigate to keystores and configure a software keystore
      {:ok, keystores_view, html} = live(conn, "/keystores")
      assert html =~ "Keystore Management"
      assert html =~ "software"

      initial_count = length(Regex.scan(~r/<tr id="keystore-/, html))

      keystores_view
      |> form("#configure-keystore-form form", %{type: "software"})
      |> render_submit()

      rendered = render(keystores_view)
      new_count = length(Regex.scan(~r/<tr id="keystore-/, rendered))
      assert new_count == initial_count + 1

      # Step 4: Navigate to ceremony and initiate one
      {:ok, ceremony_view, html} = live(conn, "/ceremony")
      assert html =~ "Key Ceremony"
      assert html =~ "ML-DSA-65"

      ceremony_view
      |> form("#initiate-ceremony-form form", %{
        algorithm: "ML-DSA-65",
        keystore_id: "1",
        threshold_k: "2",
        threshold_n: "3",
        domain_info: "e2e test domain"
      })
      |> render_submit()

      assert has_element?(ceremony_view, "#ceremony-status")
      assert has_element?(ceremony_view, "#ceremony-state", "initiated")
      assert render(ceremony_view) =~ "ML-DSA-65"

      # Step 5: Navigate to audit log and verify events are visible
      {:ok, _audit_view, html} = live(conn, "/audit-log")
      assert html =~ "Audit Log"
      assert html =~ "login"
      assert html =~ "key_generated"
      assert html =~ "did:ssdid:admin1"
    end

    test "admin: audit log filtering works end-to-end", %{conn: conn} do
      {:ok, audit_view, html} = live(conn, "/audit-log")
      assert html =~ "Audit Log"

      # Filter by action and actor
      html =
        audit_view
        |> form("#audit-filter form", %{
          action: "login",
          actor_did: "did:ssdid:admin1",
          date_from: "",
          date_to: ""
        })
        |> render_submit()

      assert html =~ "login"
    end

    test "admin: user role filtering", %{conn: conn} do
      {:ok, users_view, _html} = live(conn, "/users")

      html =
        users_view
        |> form("#user-filter form", %{role: "key_manager"})
        |> render_change()

      assert html =~ "Key Manager One"
      refute html =~ "Admin One"
    end
  end

  describe "authentication boundary" do
    test "unauthenticated user is redirected to login for all pages", %{conn: conn} do
      for path <- ["/", "/users", "/keystores", "/ceremony", "/audit-log"] do
        assert {:error, {:redirect, %{to: "/login"}}} = live(conn, path),
               "Expected redirect to /login for path #{path}"
      end
    end
  end

  describe "login and logout flow" do
    test "login -> dashboard -> logout -> redirected to login", %{conn: conn} do
      # Login
      conn =
        post(conn, ~p"/login", %{
          "session" => %{
            "did" => "did:ssdid:e2e_admin",
            "role" => "ca_admin",
            "ca_instance_id" => "1"
          }
        })

      assert redirected_to(conn) == "/"

      # Follow redirect and verify dashboard
      conn = get(recycle(conn), ~p"/")
      assert html_response(conn, 200) =~ "Dashboard"

      # Logout
      conn = delete(recycle(conn), ~p"/logout")
      assert redirected_to(conn) == "/login"

      # Verify redirect after logout
      conn = get(recycle(conn), ~p"/")
      assert redirected_to(conn) == "/login"
    end
  end
end
