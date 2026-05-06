defmodule PkiTenantWeb.Ra.RaPagesMountTest do
  @moduledoc "Mount-level smoke tests for RA portal LiveView pages."
  use PkiTenantWeb.LiveCase, async: false

  setup do
    dir = PkiMnesia.TestHelper.setup_mnesia()
    on_exit(fn -> PkiMnesia.TestHelper.teardown_mnesia(dir) end)
    {:ok, conn: build_ra_conn_for_role(:ra_admin)}
  end

  describe "RA pages — ra_admin mounts" do
    test "dashboard mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      assert is_binary(html)
    end

    test "csrs mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/csrs")
      assert is_binary(html)
    end

    test "cert-profiles mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/cert-profiles")
      assert is_binary(html)
    end

    test "certificates mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/certificates")
      assert is_binary(html)
    end

    test "api-keys mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/api-keys")
      assert is_binary(html)
    end

    test "ra-instances mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/ra-instances")
      assert is_binary(html)
    end

    test "service-configs mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/service-configs")
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

    test "welcome mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/welcome")
      assert is_binary(html)
    end

    test "validation mounts", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/validation")
      assert is_binary(html)
    end
  end

  describe "RA pages — ra_officer access" do
    test "ra_officer can access csrs" do
      conn = build_ra_conn_for_role(:ra_officer)
      {:ok, _view, html} = live(conn, "/csrs")
      assert is_binary(html)
    end

    test "auditor can access audit-log in RA portal" do
      conn = build_ra_conn_for_role(:auditor)
      {:ok, _view, html} = live(conn, "/audit-log")
      assert is_binary(html)
    end
  end
end
