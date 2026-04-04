defmodule PkiRaEngine.Api.AuthenticatedRouterTest do
  @moduledoc """
  Tests for the AuthenticatedRouter — verifies that all expected routes exist,
  require authentication, and return proper status codes.
  """

  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.Api.Router
  alias PkiRaEngine.ApiKeyManagement
  alias PkiRaEngine.UserManagement
  alias PkiRaEngine.CertProfileConfig
  alias PkiRaEngine.CsrValidation

  @opts Router.init([])

  # ── Helpers ──────────────────────────────────────────────────────────

  defp create_user! do
    {:ok, user} =
      UserManagement.create_user(nil, %{
        display_name: "Auth Test User",
        role: "ra_officer"
      })

    user
  end

  defp create_api_key!(user) do
    {:ok, %{raw_key: raw_key}} =
      ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "auth_test"})

    raw_key
  end

  defp create_profile! do
    {:ok, profile} =
      CertProfileConfig.create_profile(nil, %{
        name: "auth_profile_#{System.unique_integer([:positive])}"
      })

    profile
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

  @sample_csr_pem "-----BEGIN CERTIFICATE REQUEST-----\nMIIBtest\n-----END CERTIFICATE REQUEST-----"

  # ── Authentication requirement ──────────────────────────────────────

  describe "authentication required on all /api/v1 endpoints" do
    test "GET /api/v1/csr without auth returns 401" do
      conn =
        unauth_conn(:get, "/api/v1/csr")
        |> Router.call(@opts)

      assert conn.status == 401
      assert json(conn)["error"] == "unauthorized"
    end

    test "POST /api/v1/csr without auth returns 401" do
      conn =
        unauth_conn(:post, "/api/v1/csr", %{})
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "GET /api/v1/csr/:id without auth returns 401" do
      conn =
        unauth_conn(:get, "/api/v1/csr/1")
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "POST /api/v1/csr/:id/approve without auth returns 401" do
      conn =
        unauth_conn(:post, "/api/v1/csr/1/approve", %{})
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "POST /api/v1/csr/:id/reject without auth returns 401" do
      conn =
        unauth_conn(:post, "/api/v1/csr/1/reject", %{})
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "GET /api/v1/certificates without auth returns 401" do
      conn =
        unauth_conn(:get, "/api/v1/certificates")
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "invalid Bearer token returns 401" do
      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("authorization", "Bearer bad_token_value")
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "missing Authorization header returns 401" do
      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 401
    end
  end

  # ── Routes accessible with valid auth ───────────────────────────────

  describe "routes accessible with valid auth" do
    test "GET /api/v1/csr returns 200" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/csr", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      assert is_list(json(conn))
    end

    test "POST /api/v1/csr with valid data returns 201" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()

      body = %{"csr_pem" => @sample_csr_pem, "cert_profile_id" => profile.id}

      conn =
        auth_conn(:post, "/api/v1/csr", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 201
    end

    test "GET /api/v1/csr/:id returns 200 for existing CSR" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()
      {:ok, csr} = CsrValidation.submit_csr(nil, @sample_csr_pem, profile.id)

      conn =
        auth_conn(:get, "/api/v1/csr/#{csr.id}", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
    end

    test "POST /api/v1/csr/:id/approve returns 200 for valid approve" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()
      {:ok, csr} = CsrValidation.submit_csr(nil, @sample_csr_pem, profile.id)
      {:ok, verified} = CsrValidation.validate_csr(nil, csr.id)

      body = %{"reviewer_user_id" => user.id}

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/approve", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      assert json(conn)["status"] == "approved"
    end

    test "POST /api/v1/csr/:id/reject returns 200 for valid reject" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()
      {:ok, csr} = CsrValidation.submit_csr(nil, @sample_csr_pem, profile.id)
      {:ok, verified} = CsrValidation.validate_csr(nil, csr.id)

      body = %{"reviewer_user_id" => user.id, "reason" => "Not compliant"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/reject", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      assert json(conn)["status"] == "rejected"
    end

    test "GET /api/v1/certificates returns 200" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/certificates", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
    end
  end

  # ── Unknown routes under /api/v1 ───────────────────────────────────

  describe "unknown routes under /api/v1" do
    test "GET /api/v1/nonexistent returns 404" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/nonexistent", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 404
      assert json(conn)["error"] == "not_found"
    end

    test "DELETE /api/v1/csr/1 returns 404 (method not allowed)" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:delete, "/api/v1/csr/1", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 404
    end
  end

  # ── Health endpoint (public, no auth) ───────────────────────────────

  describe "GET /health (public)" do
    test "returns 200 without authentication" do
      conn =
        Plug.Test.conn(:get, "/health")
        |> Router.call(@opts)

      assert conn.status == 200
      body = json(conn)
      assert body["status"] == "ok"
      assert is_map(body["checks"])
      assert body["checks"]["database"] == "ok"
    end
  end

  # ── RBAC enforcement (403) ────────────────────────────────────────

  describe "RBAC enforcement — 403 for insufficient role" do
    test "ra_officer cannot access GET /api/v1/users (requires manage_ra_admins)" do
      user = create_user!()  # creates ra_officer
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/users", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
      assert json(conn)["error"] == "forbidden"
    end

    test "ra_officer cannot access POST /api/v1/cert-profiles (requires manage_cert_profiles)" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:post, "/api/v1/cert-profiles", %{"name" => "test"}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
      assert json(conn)["error"] == "forbidden"
    end

    test "ra_officer cannot access GET /api/v1/service-configs (requires manage_service_configs)" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/service-configs", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
      assert json(conn)["error"] == "forbidden"
    end

    test "ra_officer cannot access POST /api/v1/api-keys (requires manage_api_keys)" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:post, "/api/v1/api-keys", %{"ra_user_id" => user.id, "label" => "test"}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
      assert json(conn)["error"] == "forbidden"
    end

    test "auditor cannot access POST /api/v1/csr (requires process_csrs)" do
      {:ok, auditor} = UserManagement.create_user(nil, %{display_name: "Auditor", role: "auditor"})
      {:ok, %{raw_key: raw_key}} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: auditor.id, label: "audit_key"})

      conn =
        auth_conn(:post, "/api/v1/csr", %{"csr_pem" => "test", "cert_profile_id" => "test"}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
      assert json(conn)["error"] == "forbidden"
    end

    test "auditor cannot access POST /api/v1/csr/:id/approve (requires process_csrs)" do
      {:ok, auditor} = UserManagement.create_user(nil, %{display_name: "Auditor2", role: "auditor"})
      {:ok, %{raw_key: raw_key}} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: auditor.id, label: "audit_key2"})

      conn =
        auth_conn(:post, "/api/v1/csr/#{Uniq.UUID.uuid7()}/approve", %{"reviewer_user_id" => auditor.id}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 403
      assert json(conn)["error"] == "forbidden"
    end

    test "ra_officer CAN access GET /api/v1/csr (has view_csrs)" do
      user = create_user!()  # ra_officer has :view_csrs
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/csr", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
    end

    test "ra_officer CAN access POST /api/v1/csr/:id/approve (has process_csrs)" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()
      {:ok, csr} = CsrValidation.submit_csr(nil, "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----", profile.id)
      {:ok, verified} = CsrValidation.validate_csr(nil, csr.id)

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/approve", %{"reviewer_user_id" => user.id}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
    end
  end
end
