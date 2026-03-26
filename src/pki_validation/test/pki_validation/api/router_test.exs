defmodule PkiValidation.Api.RouterTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.Api.Router
  alias PkiValidation.Schema.CertificateStatus

  @opts Router.init([])

  describe "GET /health" do
    test "returns 200 with ok status" do
      conn = conn(:get, "/health") |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "ok"} = Jason.decode!(conn.resp_body)
    end
  end

  describe "POST /ocsp" do
    test "returns good for active certificate" do
      insert_cert("ROUTER001", "active")

      conn =
        conn(:post, "/ocsp", %{"serial_number" => "ROUTER001"})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "good"} = Jason.decode!(conn.resp_body)
    end

    test "returns revoked for revoked certificate" do
      insert_cert("ROUTER002", "revoked")

      conn =
        conn(:post, "/ocsp", %{"serial_number" => "ROUTER002"})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "revoked"} = Jason.decode!(conn.resp_body)
    end

    test "returns unknown for nonexistent certificate" do
      conn =
        conn(:post, "/ocsp", %{"serial_number" => "NONEXISTENT"})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "unknown"} = Jason.decode!(conn.resp_body)
    end

    test "returns 400 for missing serial_number" do
      conn =
        conn(:post, "/ocsp", %{})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 400
      assert %{"error" => _} = Jason.decode!(conn.resp_body)
    end
  end

  describe "GET /crl" do
    test "returns CRL structure" do
      conn = conn(:get, "/crl") |> Router.call(@opts)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["type"] == "X509CRL"
      assert is_list(body["revoked_certificates"])
    end
  end

  describe "malformed OCSP request body" do
    test "POST /ocsp with non-JSON body raises ParseError" do
      assert_raise Plug.Parsers.ParseError, fn ->
        conn(:post, "/ocsp", "not json{{{")
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)
      end
    end

    test "POST /ocsp with missing serial_number returns 400" do
      conn =
        conn(:post, "/ocsp", Jason.encode!(%{wrong_field: "abc"}))
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 400
    end
  end

  describe "unknown routes" do
    test "returns 404" do
      conn = conn(:get, "/unknown") |> Router.call(@opts)

      assert conn.status == 404
      assert %{"error" => "not_found"} = Jason.decode!(conn.resp_body)
    end
  end

  defp conn(method, path, params \\ nil) do
    Plug.Test.conn(method, path, params)
  end

  defp put_req_header(conn, key, value) do
    Plug.Conn.put_req_header(conn, key, value)
  end

  defp insert_cert(serial, "active") do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial,
      issuer_key_id: "019577a0-0000-7000-8000-000000000001",
      subject_dn: "CN=#{serial}.example.com,O=Test,C=MY",
      status: "active",
      not_before: ~U[2026-01-01 00:00:00.000000Z],
      not_after: ~U[2027-12-31 23:59:59.000000Z]
    })
    |> Repo.insert!()
  end

  defp insert_cert(serial, "revoked") do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial,
      issuer_key_id: "019577a0-0000-7000-8000-000000000001",
      subject_dn: "CN=#{serial}.example.com,O=Test,C=MY",
      status: "revoked",
      not_before: ~U[2026-01-01 00:00:00.000000Z],
      not_after: ~U[2027-12-31 23:59:59.000000Z],
      revoked_at: ~U[2026-06-01 00:00:00.000000Z],
      revocation_reason: "key_compromise"
    })
    |> Repo.insert!()
  end
end
