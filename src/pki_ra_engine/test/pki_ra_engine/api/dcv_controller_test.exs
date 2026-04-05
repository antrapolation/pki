defmodule PkiRaEngine.Api.DcvControllerTest do
  @moduledoc """
  HTTP-level tests for DCV controller endpoints.
  Tests create, show, verify actions plus auth and RBAC enforcement.
  """
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.Api.Router
  alias PkiRaEngine.ApiKeyManagement
  alias PkiRaEngine.UserManagement
  alias PkiRaEngine.CertProfileConfig
  alias PkiRaEngine.CsrValidation

  @opts Router.init([])

  # ── Helpers ──────────────────────────────────────────────────────────

  defp create_officer! do
    {:ok, user} =
      UserManagement.create_user(nil, %{
        display_name: "DCV Test Officer",
        role: "ra_officer"
      })
    user
  end

  defp create_api_key!(user) do
    {:ok, %{raw_key: raw_key}} =
      ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "dcv_test", key_type: "service"})
    raw_key
  end

  defp create_profile! do
    {:ok, profile} =
      CertProfileConfig.create_profile(nil, %{
        name: "dcv_profile_#{System.unique_integer([:positive])}"
      })
    profile
  end

  defp create_csr!(profile) do
    pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBdcv#{System.unique_integer([:positive])}\n-----END CERTIFICATE REQUEST-----"
    {:ok, csr} = CsrValidation.submit_csr(nil, pem, profile.id)
    csr
  end

  defp auth_conn(method, path, body, raw_key) do
    conn =
      if body do
        Plug.Test.conn(method, path, Jason.encode!(body))
      else
        Plug.Test.conn(method, path)
      end

    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer #{raw_key}")
    |> Plug.Conn.put_req_header("content-type", "application/json")
  end

  defp unauth_conn(method, path, body \\ nil) do
    conn =
      if body do
        Plug.Test.conn(method, path, Jason.encode!(body))
      else
        Plug.Test.conn(method, path)
      end
    Plug.Conn.put_req_header(conn, "content-type", "application/json")
  end

  defp json(conn), do: Jason.decode!(conn.resp_body)

  defp setup_auth(_context) do
    user = create_officer!()
    raw_key = create_api_key!(user)
    profile = create_profile!()
    csr = create_csr!(profile)
    %{user: user, raw_key: raw_key, profile: profile, csr: csr}
  end

  # ── Authentication ─────────────────────────────────────────────────

  describe "authentication required" do
    test "POST /api/v1/csr/:id/dcv without auth returns 401" do
      conn =
        unauth_conn(:post, "/api/v1/csr/#{Uniq.UUID.uuid7()}/dcv", %{})
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "GET /api/v1/csr/:id/dcv without auth returns 401" do
      conn =
        unauth_conn(:get, "/api/v1/csr/#{Uniq.UUID.uuid7()}/dcv")
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "POST /api/v1/csr/:id/dcv/verify without auth returns 401" do
      conn =
        unauth_conn(:post, "/api/v1/csr/#{Uniq.UUID.uuid7()}/dcv/verify", %{})
        |> Router.call(@opts)

      assert conn.status == 401
    end
  end

  # ── RBAC enforcement ───────────────────────────────────────────────

  describe "RBAC enforcement" do
    test "auditor cannot create DCV challenge (requires process_csrs)" do
      {:ok, auditor} = UserManagement.create_user(nil, %{display_name: "Auditor", role: "auditor"})
      {:ok, %{raw_key: raw_key}} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: auditor.id, label: "audit_dcv"})

      body = %{"method" => "http-01", "domain" => "example.com"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{Uniq.UUID.uuid7()}/dcv", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
      assert json(conn)["error"] == "forbidden"
    end

    test "auditor cannot verify DCV challenge" do
      {:ok, auditor} = UserManagement.create_user(nil, %{display_name: "Auditor2", role: "auditor"})
      {:ok, %{raw_key: raw_key}} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: auditor.id, label: "audit_dcv2"})

      conn =
        auth_conn(:post, "/api/v1/csr/#{Uniq.UUID.uuid7()}/dcv/verify", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
    end

    test "auditor cannot view DCV challenges (missing view_csrs)" do
      {:ok, auditor} = UserManagement.create_user(nil, %{display_name: "Auditor3", role: "auditor"})
      {:ok, %{raw_key: raw_key}} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: auditor.id, label: "audit_dcv3"})

      # GET /csr/:id/dcv requires :view_csrs — auditor does NOT have this
      conn =
        auth_conn(:get, "/api/v1/csr/#{Uniq.UUID.uuid7()}/dcv", nil, raw_key)
        |> Router.call(@opts)

      # auditor doesn't have :view_csrs so this should be 403
      assert conn.status == 403
    end
  end

  # ── POST /api/v1/csr/:id/dcv (create) ─────────────────────────────

  describe "POST /api/v1/csr/:id/dcv — create" do
    setup :setup_auth

    test "201 creates HTTP-01 challenge", %{raw_key: raw_key, csr: csr} do
      body = %{"method" => "http-01", "domain" => "example.com"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 201
      resp = json(conn)
      assert resp["domain"] == "example.com"
      assert resp["method"] == "http-01"
      assert resp["status"] == "pending"
      assert resp["token"] != nil
      assert resp["token_value"] != nil
      assert resp["expires_at"] != nil
      assert resp["csr_id"] == csr.id
    end

    test "201 creates DNS-01 challenge", %{raw_key: raw_key, csr: csr} do
      body = %{"method" => "dns-01", "domain" => "example.com"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 201
      resp = json(conn)
      assert resp["method"] == "dns-01"
      assert resp["status"] == "pending"
    end

    test "422 when method is missing", %{raw_key: raw_key, csr: csr} do
      body = %{"domain" => "example.com"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "method"
    end

    test "422 when domain is missing", %{raw_key: raw_key, csr: csr} do
      body = %{"method" => "http-01"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "domain"
    end

    test "422 with invalid method", %{raw_key: raw_key, csr: csr} do
      body = %{"method" => "email-01", "domain" => "example.com"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
    end

    test "201 with custom timeout_hours", %{raw_key: raw_key, csr: csr} do
      body = %{"method" => "http-01", "domain" => "example.com", "timeout_hours" => 48}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 201
    end
  end

  # ── GET /api/v1/csr/:id/dcv (show) ────────────────────────────────

  describe "GET /api/v1/csr/:id/dcv — show" do
    setup :setup_auth

    test "returns list of challenges for CSR", %{raw_key: raw_key, csr: csr} do
      # Create two challenges
      PkiRaEngine.DcvChallenge.create(nil, csr.id, "a.example.com", "http-01", nil)
      PkiRaEngine.DcvChallenge.create(nil, csr.id, "b.example.com", "dns-01", nil)

      conn =
        auth_conn(:get, "/api/v1/csr/#{csr.id}/dcv", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert is_list(resp)
      assert length(resp) == 2
    end

    test "returns empty list for CSR with no challenges", %{raw_key: raw_key, csr: csr} do
      conn =
        auth_conn(:get, "/api/v1/csr/#{csr.id}/dcv", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      assert json(conn) == []
    end
  end

  # ── POST /api/v1/csr/:id/dcv/verify ───────────────────────────────

  describe "POST /api/v1/csr/:id/dcv/verify" do
    setup :setup_auth

    test "returns results for pending challenges (empty when none)", %{raw_key: raw_key, csr: csr} do
      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv/verify", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      assert json(conn) == []
    end

    test "returns results array matching pending challenge count", %{raw_key: raw_key, csr: csr} do
      PkiRaEngine.DcvChallenge.create(nil, csr.id, "verify.example.com", "http-01", nil)

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/dcv/verify", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert is_list(resp)
      assert length(resp) == 1
      # Verification will fail (no actual HTTP server), but the response should still be returned
      assert hd(resp)["domain"] == "verify.example.com"
    end
  end
end
