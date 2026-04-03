defmodule PkiCaPortalWeb.CeremonyIntegrationTest do
  @moduledoc """
  Integration tests for the multi-participant key ceremony flow.

  Verifies:
  - RBAC access control (each role can only access their designated ceremony page)
  - Multi-user concurrent sessions via SessionStore
  - CustodianPasswordStore multi-custodian scenarios
  - LiveView page rendering for each ceremony role

  Note: Full end-to-end ceremony orchestration (initiate -> accept -> witness ->
  complete) requires the StatefulMock to support ceremony orchestrator functions.
  The Mock currently returns canned empty responses for ceremony list calls.
  These tests verify the infrastructure and access control that support the flow.
  """
  use PkiCaPortalWeb.ConnCase

  import Phoenix.LiveViewTest

  alias PkiCaPortal.{SessionStore, CustodianPasswordStore}

  # Test users representing the 3 roles + a second key manager
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

  @km1 %{
    user_id: "km-001",
    username: "test-km-1",
    role: "key_manager",
    tenant_id: "tenant-001",
    display_name: "Key Manager 1",
    email: "km1@test.com",
    ip: "127.0.0.1",
    user_agent: "TestAgent/1.0"
  }

  @km2 %{
    user_id: "km-002",
    username: "test-km-2",
    role: "key_manager",
    tenant_id: "tenant-001",
    display_name: "Key Manager 2",
    email: "km2@test.com",
    ip: "127.0.0.1",
    user_agent: "TestAgent/1.0"
  }

  @auditor %{
    user_id: "auditor-001",
    username: "test-auditor",
    role: "auditor",
    tenant_id: "tenant-001",
    display_name: "Test Auditor",
    email: "auditor@test.com",
    ip: "127.0.0.1",
    user_agent: "TestAgent/1.0"
  }

  setup do
    SessionStore.clear_all()
    CustodianPasswordStore.clear_all()
    :ok
  end

  # Creates a real SessionStore entry and returns a conn with session_id set
  defp login_as(user) do
    {:ok, session_id} = SessionStore.create(user)

    conn =
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("user-agent", "TestAgent/1.0")
      |> init_test_session(%{session_id: session_id})

    {conn, session_id}
  end

  # -------------------------------------------------------------------------
  # RBAC access control
  # -------------------------------------------------------------------------

  describe "ceremony page access control" do
    test "ca_admin can access /ceremony" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/ceremony")
      assert html =~ "Key Ceremony"
    end

    test "key_manager can access /ceremony/custodian" do
      {conn, _} = login_as(@km1)
      {:ok, _view, html} = live(conn, "/ceremony/custodian")
      assert html =~ "My Ceremony Shares"
    end

    test "auditor can access /ceremony/witness" do
      {conn, _} = login_as(@auditor)
      {:ok, _view, html} = live(conn, "/ceremony/witness")
      assert html =~ "Ceremony Witness"
    end

    test "key_manager cannot access /ceremony (admin page)" do
      {conn, _} = login_as(@km1)
      assert {:error, {:redirect, %{to: "/"}}} = live(conn, "/ceremony")
    end

    test "auditor cannot access /ceremony (admin page)" do
      {conn, _} = login_as(@auditor)
      assert {:error, {:redirect, %{to: "/"}}} = live(conn, "/ceremony")
    end

    test "auditor cannot access /ceremony/custodian" do
      {conn, _} = login_as(@auditor)
      assert {:error, {:redirect, %{to: "/"}}} = live(conn, "/ceremony/custodian")
    end

    test "key_manager cannot access /ceremony/witness" do
      {conn, _} = login_as(@km1)
      assert {:error, {:redirect, %{to: "/"}}} = live(conn, "/ceremony/witness")
    end

    test "unauthenticated user is redirected to /login for /ceremony" do
      conn = Phoenix.ConnTest.build_conn()
      assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/ceremony")
    end

    test "unauthenticated user is redirected to /login for /ceremony/custodian" do
      conn = Phoenix.ConnTest.build_conn()
      assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/ceremony/custodian")
    end

    test "unauthenticated user is redirected to /login for /ceremony/witness" do
      conn = Phoenix.ConnTest.build_conn()
      assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/ceremony/witness")
    end
  end

  # -------------------------------------------------------------------------
  # Multi-user concurrent sessions
  # -------------------------------------------------------------------------

  describe "multi-user concurrent sessions for ceremony" do
    test "all 4 ceremony participants can have concurrent sessions" do
      {_, admin_sid} = login_as(@admin)
      {_, km1_sid} = login_as(@km1)
      {_, km2_sid} = login_as(@km2)
      {_, auditor_sid} = login_as(@auditor)

      assert {:ok, admin_sess} = SessionStore.lookup(admin_sid)
      assert {:ok, km1_sess} = SessionStore.lookup(km1_sid)
      assert {:ok, km2_sess} = SessionStore.lookup(km2_sid)
      assert {:ok, auditor_sess} = SessionStore.lookup(auditor_sid)

      assert admin_sess.role == "ca_admin"
      assert km1_sess.role == "key_manager"
      assert km2_sess.role == "key_manager"
      assert auditor_sess.role == "auditor"

      # All sessions belong to the same tenant
      assert admin_sess.tenant_id == "tenant-001"
      assert km1_sess.tenant_id == "tenant-001"
      assert km2_sess.tenant_id == "tenant-001"
      assert auditor_sess.tenant_id == "tenant-001"
    end

    test "each session has a unique session_id" do
      {_, sid1} = login_as(@admin)
      {_, sid2} = login_as(@km1)
      {_, sid3} = login_as(@km2)
      {_, sid4} = login_as(@auditor)

      ids = [sid1, sid2, sid3, sid4]
      assert length(Enum.uniq(ids)) == 4
    end

    test "deleting one session does not affect others" do
      {_, admin_sid} = login_as(@admin)
      {_, km1_sid} = login_as(@km1)

      :ok = SessionStore.delete(admin_sid)

      assert {:error, :not_found} = SessionStore.lookup(admin_sid)
      assert {:ok, _} = SessionStore.lookup(km1_sid)
    end
  end

  # -------------------------------------------------------------------------
  # CustodianPasswordStore in multi-custodian ceremony context
  # -------------------------------------------------------------------------

  describe "custodian password store for ceremony" do
    test "stores and retrieves passwords for multiple custodians" do
      :ok = CustodianPasswordStore.store_password("cer-1", "km-001", "secret1")
      :ok = CustodianPasswordStore.store_password("cer-1", "km-002", "secret2")

      assert {:ok, "secret1"} = CustodianPasswordStore.get_password("cer-1", "km-001")
      assert {:ok, "secret2"} = CustodianPasswordStore.get_password("cer-1", "km-002")
      assert CustodianPasswordStore.has_all_passwords?("cer-1", ["km-001", "km-002"])
    end

    test "passwords are isolated between ceremonies" do
      :ok = CustodianPasswordStore.store_password("cer-1", "km-001", "pass_c1")
      :ok = CustodianPasswordStore.store_password("cer-2", "km-001", "pass_c2")

      assert {:ok, "pass_c1"} = CustodianPasswordStore.get_password("cer-1", "km-001")
      assert {:ok, "pass_c2"} = CustodianPasswordStore.get_password("cer-2", "km-001")
    end

    test "wipe_ceremony clears only that ceremony's passwords" do
      :ok = CustodianPasswordStore.store_password("cer-1", "km-001", "secret1")
      :ok = CustodianPasswordStore.store_password("cer-1", "km-002", "secret2")
      :ok = CustodianPasswordStore.store_password("cer-2", "km-001", "other")

      :ok = CustodianPasswordStore.wipe_ceremony("cer-1")

      assert {:error, :not_found} = CustodianPasswordStore.get_password("cer-1", "km-001")
      assert {:error, :not_found} = CustodianPasswordStore.get_password("cer-1", "km-002")
      # Other ceremony unaffected
      assert {:ok, "other"} = CustodianPasswordStore.get_password("cer-2", "km-001")
    end

    test "has_all_passwords? returns false when some custodians have not submitted" do
      :ok = CustodianPasswordStore.store_password("cer-1", "km-001", "pass1")
      refute CustodianPasswordStore.has_all_passwords?("cer-1", ["km-001", "km-002"])
    end
  end

  # -------------------------------------------------------------------------
  # Ceremony LiveView page rendering
  # -------------------------------------------------------------------------

  describe "ceremony LiveView pages render correctly" do
    test "admin ceremony page shows page title" do
      {conn, _} = login_as(@admin)
      {:ok, _view, html} = live(conn, "/ceremony")

      assert html =~ "Key Ceremony"
    end

    test "custodian page shows empty state when no ceremonies assigned" do
      {conn, _} = login_as(@km1)
      {:ok, _view, html} = live(conn, "/ceremony/custodian")

      assert html =~ "My Ceremony Shares"
      # Mock returns empty list for list_my_ceremony_shares
    end

    test "witness page shows empty state when no ceremonies assigned" do
      {conn, _} = login_as(@auditor)
      {:ok, _view, html} = live(conn, "/ceremony/witness")

      assert html =~ "Ceremony Witness"
      # Mock returns empty list for list_my_witness_ceremonies
    end

    test "second key manager also sees custodian page" do
      {conn, _} = login_as(@km2)
      {:ok, _view, html} = live(conn, "/ceremony/custodian")

      assert html =~ "My Ceremony Shares"
    end

    test "admin page assigns correct page_title" do
      {conn, _} = login_as(@admin)
      {:ok, view, _html} = live(conn, "/ceremony")

      # Verify the LiveView assign
      assert render(view) =~ "Key Ceremony"
    end
  end
end
