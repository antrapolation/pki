defmodule PkiTenantWeb.HealthControllerTest do
  use PkiTenantWeb.ConnCase

  describe "GET /health via CaRouter" do
    test "returns JSON with expected keys", %{conn: conn} do
      conn = conn |> Phoenix.ConnTest.dispatch(PkiTenantWeb.CaRouter, :get, "/health")
      body = json_response(conn, conn.status)

      assert is_map(body)
      assert Map.has_key?(body, "status")
      assert Map.has_key?(body, "mnesia")
      assert Map.has_key?(body, "tables")
      assert Map.has_key?(body, "active_keys")
      assert Map.has_key?(body, "uptime_seconds")
      assert Map.has_key?(body, "last_backup")
    end

    test "returns 200 when healthy or 503 when degraded", %{conn: conn} do
      conn = conn |> Phoenix.ConnTest.dispatch(PkiTenantWeb.CaRouter, :get, "/health")
      assert conn.status in [200, 503]
    end
  end

  describe "GET /health via RaRouter" do
    test "returns JSON with expected keys", %{conn: conn} do
      conn = conn |> Phoenix.ConnTest.dispatch(PkiTenantWeb.RaRouter, :get, "/health")
      body = json_response(conn, conn.status)

      assert is_map(body)
      assert Map.has_key?(body, "status")
      assert Map.has_key?(body, "mnesia")
    end

    test "returns 200 when healthy or 503 when degraded", %{conn: conn} do
      conn = conn |> Phoenix.ConnTest.dispatch(PkiTenantWeb.RaRouter, :get, "/health")
      assert conn.status in [200, 503]
    end
  end
end
