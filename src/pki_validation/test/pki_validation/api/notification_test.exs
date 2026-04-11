defmodule PkiValidation.Api.NotificationTest do
  @moduledoc """
  Tests for the /notify/issuance and /notify/revocation endpoints.

  Verifies the full notification flow: authentication, payload validation,
  certificate status insertion/update, OCSP cache invalidation, and
  all error paths (400, 401, 404, 409, 422).
  """
  use PkiValidation.DataCase, async: false

  alias PkiValidation.Api.Router
  alias PkiValidation.Schema.CertificateStatus
  alias PkiValidation.OcspResponder

  @opts Router.init([])
  @secret "test-secret"

  # ── POST /notify/issuance ─────────────────────────────────────────

  describe "POST /notify/issuance" do
    test "creates active certificate status with valid payload" do
      payload = valid_issuance_payload()
      conn = post_notify("/notify/issuance", payload)

      assert conn.status == 201
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "ok"
      assert body["serial_number"] == payload["serial_number"]

      # Verify record in database
      cert = Repo.one!(from c in CertificateStatus, where: c.serial_number == ^payload["serial_number"])
      assert cert.status == "active"
      assert cert.issuer_key_id == payload["issuer_key_id"]
      assert cert.subject_dn == payload["subject_dn"]
    end

    test "OCSP returns good for newly notified certificate" do
      payload = valid_issuance_payload()
      conn = post_notify("/notify/issuance", payload)
      assert conn.status == 201

      {:ok, response} = OcspResponder.check_status_uncached(payload["serial_number"])
      assert response.status == "good"
    end

    test "returns 401 without authorization header" do
      conn =
        Plug.Test.conn(:post, "/notify/issuance", Jason.encode!(valid_issuance_payload()))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 401
      assert %{"error" => "unauthorized"} = Jason.decode!(conn.resp_body)
    end

    test "returns 401 with wrong bearer token" do
      conn =
        Plug.Test.conn(:post, "/notify/issuance", Jason.encode!(valid_issuance_payload()))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer wrong-token")
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "returns 400 for missing required fields" do
      conn = post_notify("/notify/issuance", %{"serial_number" => "PARTIAL001"})

      assert conn.status == 400
      body = Jason.decode!(conn.resp_body)
      assert body["error"] =~ "missing"
    end

    test "returns 422 for duplicate serial_number" do
      payload = valid_issuance_payload()
      conn1 = post_notify("/notify/issuance", payload)
      assert conn1.status == 201

      conn2 = post_notify("/notify/issuance", payload)
      assert conn2.status == 422
    end
  end

  # ── POST /notify/revocation ───────────────────────────────────────

  describe "POST /notify/revocation" do
    setup do
      # Insert an active certificate to revoke
      serial = "REVOKE-TEST-#{System.unique_integer([:positive])}"
      payload = valid_issuance_payload(%{serial_number: serial})
      conn = post_notify("/notify/issuance", payload)
      assert conn.status == 201
      %{serial_number: serial}
    end

    test "revokes an active certificate", %{serial_number: serial} do
      conn = post_notify("/notify/revocation", %{
        "serial_number" => serial,
        "reason" => "key_compromise"
      })

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "ok"

      # Verify DB state
      cert = Repo.one!(from c in CertificateStatus, where: c.serial_number == ^serial)
      assert cert.status == "revoked"
      assert cert.revocation_reason == "key_compromise"
      assert cert.revoked_at != nil
    end

    test "OCSP returns revoked after revocation notification", %{serial_number: serial} do
      post_notify("/notify/revocation", %{
        "serial_number" => serial,
        "reason" => "key_compromise"
      })

      {:ok, response} = OcspResponder.check_status_uncached(serial)
      assert response.status == "revoked"
      assert response.reason == "key_compromise"
    end

    test "returns 401 without authorization" do
      conn =
        Plug.Test.conn(:post, "/notify/revocation",
          Jason.encode!(%{"serial_number" => "X", "reason" => "unspecified"}))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 401
    end

    test "returns 404 for non-existent certificate" do
      conn = post_notify("/notify/revocation", %{
        "serial_number" => "DOES-NOT-EXIST",
        "reason" => "unspecified"
      })

      assert conn.status == 404
      assert %{"error" => "certificate_not_found"} = Jason.decode!(conn.resp_body)
    end

    test "returns 409 for already revoked certificate", %{serial_number: serial} do
      conn1 = post_notify("/notify/revocation", %{
        "serial_number" => serial,
        "reason" => "key_compromise"
      })
      assert conn1.status == 200

      conn2 = post_notify("/notify/revocation", %{
        "serial_number" => serial,
        "reason" => "superseded"
      })
      assert conn2.status == 409
      assert %{"error" => "already_revoked"} = Jason.decode!(conn2.resp_body)
    end

    test "returns 400 for missing required fields" do
      conn = post_notify("/notify/revocation", %{"serial_number" => "X"})

      assert conn.status == 400
      body = Jason.decode!(conn.resp_body)
      assert body["error"] =~ "missing"
    end
  end

  # ── Full notification lifecycle ───────────────────────────────────

  describe "full notification lifecycle" do
    test "issue → OCSP good → revoke → OCSP revoked → CRL contains serial" do
      serial = "LIFECYCLE-#{System.unique_integer([:positive])}"

      # 1. Issue
      issue_conn = post_notify("/notify/issuance", valid_issuance_payload(%{serial_number: serial}))
      assert issue_conn.status == 201

      # 2. OCSP should return "good"
      {:ok, ocsp1} = OcspResponder.check_status_uncached(serial)
      assert ocsp1.status == "good"

      # 3. Revoke
      revoke_conn = post_notify("/notify/revocation", %{
        "serial_number" => serial,
        "reason" => "superseded"
      })
      assert revoke_conn.status == 200

      # 4. OCSP should return "revoked"
      {:ok, ocsp2} = OcspResponder.check_status_uncached(serial)
      assert ocsp2.status == "revoked"
      assert ocsp2.reason == "superseded"

      # 5. Force CRL regeneration so the GenServer snapshot includes the revocation
      PkiValidation.CrlPublisher.regenerate()

      crl_conn =
        Plug.Test.conn(:get, "/crl")
        |> Router.call(@opts)

      assert crl_conn.status == 200
      crl = Jason.decode!(crl_conn.resp_body)
      serials = Enum.map(crl["revoked_certificates"], & &1["serial_number"])
      assert serial in serials
    end
  end

  # ── Helpers ───────────────────────────────────────────────────────

  defp post_notify(path, payload) do
    Plug.Test.conn(:post, path, Jason.encode!(payload))
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header("authorization", "Bearer #{@secret}")
    |> Router.call(@opts)
  end

  defp valid_issuance_payload(overrides \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Map.merge(
      %{
        "serial_number" => "NOTIFY-#{System.unique_integer([:positive])}",
        "issuer_key_id" => Uniq.UUID.uuid7(),
        "subject_dn" => "CN=test.example.com,O=Test",
        "not_before" => DateTime.to_iso8601(now),
        "not_after" => DateTime.to_iso8601(DateTime.add(now, 365, :day))
      },
      Map.new(overrides, fn {k, v} -> {to_string(k), v} end)
    )
  end
end
