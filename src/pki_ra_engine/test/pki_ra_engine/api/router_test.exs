defmodule PkiRaEngine.Api.RouterTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.Api.Router
  alias PkiRaEngine.ApiKeyManagement
  alias PkiRaEngine.UserManagement
  alias PkiRaEngine.CertProfileConfig
  alias PkiRaEngine.CsrValidation

  @opts Router.init([])

  defp create_user! do
    {:ok, user} =
      UserManagement.create_user(%{
        display_name: "API User",
        role: "ra_officer"
      })

    user
  end

  defp create_api_key!(user) do
    {:ok, %{raw_key: raw_key}} =
      ApiKeyManagement.create_api_key(%{ra_user_id: user.id, label: "test"})

    raw_key
  end

  defp create_profile! do
    {:ok, profile} =
      CertProfileConfig.create_profile(%{
        name: "api_test_profile_#{System.unique_integer([:positive])}"
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

  defp json_response(conn) do
    Jason.decode!(conn.resp_body)
  end

  describe "GET /health" do
    test "returns 200 ok" do
      conn =
        :get
        |> Plug.Test.conn("/health")
        |> Router.call(@opts)

      assert conn.status == 200
      assert json_response(conn) == %{"status" => "ok"}
    end
  end

  describe "authentication" do
    test "POST /api/v1/csr without auth returns 401" do
      conn =
        :post
        |> Plug.Test.conn("/api/v1/csr", Jason.encode!(%{}))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 401
      assert json_response(conn)["error"] == "unauthorized"
    end

    test "POST /api/v1/csr with invalid key returns 401" do
      conn =
        auth_conn(:post, "/api/v1/csr", %{}, "invalid_key_data")
        |> Router.call(@opts)

      assert conn.status == 401
    end
  end

  describe "POST /api/v1/csr" do
    test "creates a CSR with valid auth" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()

      body = %{
        "csr_pem" => "-----BEGIN CERTIFICATE REQUEST-----\nMIIBtest\n-----END CERTIFICATE REQUEST-----",
        "cert_profile_id" => profile.id
      }

      conn =
        auth_conn(:post, "/api/v1/csr", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 201
      resp = json_response(conn)
      # CSR is auto-validated after submission, so status will be "verified"
      assert resp["data"]["status"] in ["pending", "verified"]
      assert resp["data"]["id"] != nil
    end
  end

  describe "GET /api/v1/csr" do
    test "lists CSRs" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()

      CsrValidation.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----", profile.id)

      conn =
        auth_conn(:get, "/api/v1/csr", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json_response(conn)
      assert is_list(resp["data"])
    end

    test "filters CSRs by status" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----", profile.id)
      CsrValidation.validate_csr(csr.id)

      conn =
        auth_conn(:get, "/api/v1/csr?status=verified", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json_response(conn)
      assert length(resp["data"]) >= 1
      assert Enum.all?(resp["data"], &(&1["status"] == "verified"))
    end
  end

  describe "GET /api/v1/csr/:id" do
    test "returns a CSR by id" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----", profile.id)

      conn =
        auth_conn(:get, "/api/v1/csr/#{csr.id}", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json_response(conn)
      assert resp["data"]["id"] == csr.id
    end

    test "returns 404 for non-existent CSR" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/csr/#{Uniq.UUID.uuid7()}", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 404
    end
  end

  describe "POST /api/v1/csr/:id/approve" do
    test "approves a verified CSR" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----", profile.id)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      body = %{"reviewer_user_id" => user.id}

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/approve", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json_response(conn)
      assert resp["data"]["status"] == "approved"
    end
  end

  describe "POST /api/v1/csr/:id/reject" do
    test "rejects a verified CSR" do
      user = create_user!()
      raw_key = create_api_key!(user)
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----", profile.id)
      {:ok, verified} = CsrValidation.validate_csr(csr.id)

      body = %{"reviewer_user_id" => user.id, "reason" => "Policy violation"}

      conn =
        auth_conn(:post, "/api/v1/csr/#{verified.id}/reject", body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json_response(conn)
      assert resp["data"]["status"] == "rejected"
    end
  end

  describe "D10: missing body params return 422" do
    test "POST /api/v1/csr with empty body returns 422" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:post, "/api/v1/csr", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      resp = json_response(conn)
      assert resp["error"] =~ "missing required field"
    end

    test "POST /api/v1/csr/:id/approve with empty body returns 422" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:post, "/api/v1/csr/1/approve", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      resp = json_response(conn)
      assert resp["error"] =~ "missing required field"
    end

    test "POST /api/v1/csr/:id/reject with empty body returns 422" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:post, "/api/v1/csr/1/reject", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
      resp = json_response(conn)
      assert resp["error"] =~ "missing required field"
    end
  end

  describe "D11: non-existent UUID path ID returns 404" do
    test "GET /api/v1/csr/<uuid> returns 404 for non-existent" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/csr/#{Uniq.UUID.uuid7()}", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 404
      resp = json_response(conn)
      assert resp["error"] == "not_found"
    end
  end

  describe "malformed request handling" do
    test "POST /api/v1/csr with non-JSON body raises ParseError" do
      user = create_user!()
      raw_key = create_api_key!(user)

      assert_raise Plug.Parsers.ParseError, fn ->
        Plug.Test.conn(:post, "/api/v1/csr", "this is not json{{{")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{raw_key}")
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@opts)
      end
    end

    test "POST /api/v1/csr with empty body returns 422" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:post, "/api/v1/csr", %{}, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
    end
  end

  describe "unknown routes" do
    test "returns 404 for unknown authenticated routes" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        auth_conn(:get, "/api/v1/unknown", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 404
    end
  end
end
