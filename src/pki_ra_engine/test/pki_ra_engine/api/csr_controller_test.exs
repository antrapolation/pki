defmodule PkiRaEngine.Api.CsrControllerTest do
  @moduledoc """
  Unit tests for CsrController — exercises each action function directly
  through the Router (since controllers are invoked via Plug.Router dispatch).
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
      UserManagement.create_user(%{
        did: "did:example:ctrl_#{System.unique_integer([:positive])}",
        display_name: "Controller Test User",
        role: "ra_officer"
      })

    user
  end

  defp create_api_key!(user) do
    {:ok, %{raw_key: raw_key}} =
      ApiKeyManagement.create_api_key(%{ra_user_id: user.id, label: "ctrl_test"})

    raw_key
  end

  defp create_profile! do
    {:ok, profile} =
      CertProfileConfig.create_profile(%{
        name: "ctrl_profile_#{System.unique_integer([:positive])}"
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

  defp json(conn), do: Jason.decode!(conn.resp_body)

  defp setup_auth(_context) do
    user = create_user!()
    raw_key = create_api_key!(user)
    profile = create_profile!()
    %{user: user, raw_key: raw_key, profile: profile}
  end

  @sample_csr_pem "-----BEGIN CERTIFICATE REQUEST-----\nMIIBtest\n-----END CERTIFICATE REQUEST-----"

  # ── POST /api/v1/csr (submit) ───────────────────────────────────────

  describe "POST /api/v1/csr — submit" do
    setup :setup_auth

    test "201 with valid csr_pem and cert_profile_id", %{raw_key: raw_key, profile: profile} do
      body = %{"csr_pem" => @sample_csr_pem, "cert_profile_id" => profile.id}

      conn =
        auth_conn(:post, "/api/v1/csr", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 201
      resp = json(conn)
      assert resp["data"]["id"] != nil
      assert resp["data"]["csr_pem"] == @sample_csr_pem
      assert resp["data"]["cert_profile_id"] == profile.id
      assert resp["data"]["status"] in ["pending", "verified"]
      assert resp["data"]["submitted_at"] != nil
    end

    test "422 when csr_pem is missing", %{raw_key: raw_key, profile: profile} do
      body = %{"cert_profile_id" => profile.id}

      conn =
        auth_conn(:post, "/api/v1/csr", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "csr_pem"
    end

    test "422 when cert_profile_id is missing", %{raw_key: raw_key} do
      body = %{"csr_pem" => @sample_csr_pem}

      conn =
        auth_conn(:post, "/api/v1/csr", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "cert_profile_id"
    end

    test "422 when body is empty", %{raw_key: raw_key} do
      conn =
        auth_conn(:post, "/api/v1/csr", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "missing required field"
    end
  end

  # ── GET /api/v1/csr (list) ──────────────────────────────────────────

  describe "GET /api/v1/csr — list" do
    setup :setup_auth

    test "returns list of CSRs", %{raw_key: raw_key, profile: profile} do
      CsrValidation.submit_csr(@sample_csr_pem, profile.id)
      CsrValidation.submit_csr(@sample_csr_pem, profile.id)

      conn =
        auth_conn(:get, "/api/v1/csr", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert is_list(resp["data"])
      assert length(resp["data"]) == 2
    end

    test "filters by status=pending", %{raw_key: raw_key, profile: profile} do
      {:ok, csr1} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)
      {:ok, _csr2} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)
      # validate one so it moves to verified
      CsrValidation.validate_csr(csr1.id)

      conn =
        auth_conn(:get, "/api/v1/csr?status=pending", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert Enum.all?(resp["data"], &(&1["status"] == "pending"))
    end

    test "filters by status=verified", %{raw_key: raw_key, profile: profile} do
      {:ok, csr} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)
      CsrValidation.validate_csr(csr.id)

      conn =
        auth_conn(:get, "/api/v1/csr?status=verified", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert length(resp["data"]) >= 1
      assert Enum.all?(resp["data"], &(&1["status"] == "verified"))
    end

    test "returns empty list when no CSRs exist", %{raw_key: raw_key} do
      conn =
        auth_conn(:get, "/api/v1/csr", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      assert json(conn)["data"] == []
    end
  end

  # ── GET /api/v1/csr/:id (show) ─────────────────────────────────────

  describe "GET /api/v1/csr/:id — show" do
    setup :setup_auth

    test "200 with CSR detail", %{raw_key: raw_key, profile: profile} do
      {:ok, csr} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)

      conn =
        auth_conn(:get, "/api/v1/csr/#{csr.id}", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert resp["data"]["id"] == csr.id
      assert resp["data"]["csr_pem"] == @sample_csr_pem
      assert resp["data"]["subject_dn"] != nil
    end

    test "404 for non-existent CSR id", %{raw_key: raw_key} do
      conn =
        auth_conn(:get, "/api/v1/csr/99999", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 404
      assert json(conn)["error"] == "not_found"
    end

    test "400 for non-integer id", %{raw_key: raw_key} do
      conn =
        auth_conn(:get, "/api/v1/csr/not-a-number", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 400
      assert json(conn)["error"] =~ "invalid id"
    end
  end

  # ── POST /api/v1/csr/:id/approve ───────────────────────────────────

  describe "POST /api/v1/csr/:id/approve" do
    setup :setup_auth

    test "approves a verified CSR", %{user: user, raw_key: raw_key, profile: profile} do
      {:ok, csr} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      body = %{"reviewer_user_id" => user.id}

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/approve", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert resp["data"]["status"] == "approved"
      assert resp["data"]["reviewed_by"] == user.id
    end

    test "422 when CSR is still pending (invalid transition)", %{user: user, raw_key: raw_key, profile: profile} do
      {:ok, csr} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)

      body = %{"reviewer_user_id" => user.id}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/approve", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
    end

    test "404 for non-existent CSR", %{user: user, raw_key: raw_key} do
      body = %{"reviewer_user_id" => user.id}

      conn =
        auth_conn(:post, "/api/v1/csr/99999/approve", body, raw_key)
        |> Router.call(@opts)

      assert conn.status in [404, 422]
    end

    test "422 when reviewer_user_id is missing", %{raw_key: raw_key} do
      conn =
        auth_conn(:post, "/api/v1/csr/1/approve", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "missing required field"
    end
  end

  # ── POST /api/v1/csr/:id/reject ────────────────────────────────────

  describe "POST /api/v1/csr/:id/reject" do
    setup :setup_auth

    test "rejects a verified CSR with reason", %{user: user, raw_key: raw_key, profile: profile} do
      {:ok, csr} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      body = %{
        "reviewer_user_id" => user.id,
        "reason" => "Policy violation"
      }

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/reject", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json(conn)
      assert resp["data"]["status"] == "rejected"
      assert resp["data"]["rejection_reason"] == "Policy violation"
      assert resp["data"]["reviewed_by"] == user.id
    end

    test "422 when reason is missing", %{user: user, raw_key: raw_key, profile: profile} do
      {:ok, csr} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      body = %{"reviewer_user_id" => user.id}

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/reject", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "reason"
    end

    test "422 when body is empty", %{raw_key: raw_key} do
      conn =
        auth_conn(:post, "/api/v1/csr/1/reject", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      assert json(conn)["error"] =~ "missing required field"
    end

    test "422 when CSR is still pending (invalid transition)", %{user: user, raw_key: raw_key, profile: profile} do
      {:ok, csr} = CsrValidation.submit_csr(@sample_csr_pem, profile.id)

      body = %{"reviewer_user_id" => user.id, "reason" => "bad"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/reject", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
    end
  end
end
