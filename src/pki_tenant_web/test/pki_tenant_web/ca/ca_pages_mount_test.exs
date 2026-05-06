defmodule PkiTenantWeb.Ca.CaPagesMountTest do
  @moduledoc "Mount-level smoke tests for CA portal LiveView pages."
  use PkiTenantWeb.LiveCase, async: false

  describe "CA pages — ca_admin mounts" do
    test "dashboard mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      assert html =~ "Dashboard" or html =~ "CA Portal"
    end

    test "ca-instances mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/ca-instances")
      assert is_binary(html)
    end

    test "users mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/users")
      assert is_binary(html)
    end

    test "audit-log mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/audit-log")
      assert is_binary(html)
    end

    test "hsm-devices mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/hsm-devices")
      assert is_binary(html)
    end

    test "keystores mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/keystores")
      assert is_binary(html)
    end

    test "ceremonies mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/ceremonies")
      assert is_binary(html)
    end

    test "profile mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/profile")
      assert is_binary(html)
    end
  end

  describe "CA pages — role-based access" do
    test "auditor can access dashboard" do
      conn = build_conn_for_role(:auditor)
      {:ok, _view, html} = live(conn, "/")
      assert is_binary(html)
    end

    test "auditor can access audit-log" do
      conn = build_conn_for_role(:auditor)
      {:ok, _view, html} = live(conn, "/audit-log")
      assert is_binary(html)
    end

    test "auditor can access ca-instances" do
      conn = build_conn_for_role(:auditor)
      {:ok, _view, html} = live(conn, "/ca-instances")
      assert is_binary(html)
    end

    test "auditor is redirected from users page" do
      conn = build_conn_for_role(:auditor)
      assert {:error, {:redirect, _}} = live(conn, "/users")
    end

    test "auditor is redirected from ceremonies page" do
      conn = build_conn_for_role(:auditor)
      assert {:error, {:redirect, _}} = live(conn, "/ceremonies")
    end

    test "key_manager can access ceremonies" do
      conn = build_conn_for_role(:key_manager)
      {:ok, _view, html} = live(conn, "/ceremonies")
      assert is_binary(html)
    end
  end
end
