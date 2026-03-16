defmodule PkiValidation.IntegrationTest do
  @moduledoc """
  Integration tests that verify OCSP and CRL work together correctly.
  """
  use PkiValidation.DataCase

  alias PkiValidation.Api.Router
  alias PkiValidation.CrlPublisher
  alias PkiValidation.OcspResponder
  alias PkiValidation.Schema.CertificateStatus

  @router_opts Router.init([])

  describe "end-to-end validation flow" do
    setup do
      # Insert test certificates
      insert_cert(%{
        serial_number: "INT001",
        issuer_key_id: 1,
        subject_dn: "CN=active.example.com,O=Test,C=MY",
        status: "active",
        not_before: ~U[2026-01-01 00:00:00.000000Z],
        not_after: ~U[2027-12-31 23:59:59.000000Z]
      })

      insert_cert(%{
        serial_number: "INT002",
        issuer_key_id: 1,
        subject_dn: "CN=revoked.example.com,O=Test,C=MY",
        status: "revoked",
        not_before: ~U[2026-01-01 00:00:00.000000Z],
        not_after: ~U[2027-12-31 23:59:59.000000Z],
        revoked_at: ~U[2026-06-15 00:00:00.000000Z],
        revocation_reason: "key_compromise"
      })

      insert_cert(%{
        serial_number: "INT003",
        issuer_key_id: 1,
        subject_dn: "CN=another-revoked.example.com,O=Test,C=MY",
        status: "revoked",
        not_before: ~U[2026-01-01 00:00:00.000000Z],
        not_after: ~U[2027-12-31 23:59:59.000000Z],
        revoked_at: ~U[2026-07-01 00:00:00.000000Z],
        revocation_reason: "superseded"
      })

      :ok
    end

    test "OCSP returns correct status for active certificate" do
      {:ok, response} = OcspResponder.check_status_uncached("INT001")
      assert response.status == "good"
      assert response.serial_number == "INT001"
    end

    test "OCSP returns correct status for revoked certificate" do
      {:ok, response} = OcspResponder.check_status_uncached("INT002")
      assert response.status == "revoked"
      assert response.reason == "key_compromise"
    end

    test "OCSP returns unknown for nonexistent certificate" do
      {:ok, response} = OcspResponder.check_status_uncached("NONEXISTENT")
      assert response.status == "unknown"
    end

    test "CRL contains all revoked certificates" do
      crl = CrlPublisher.generate_crl()
      assert crl.total_revoked == 2

      serials = Enum.map(crl.revoked_certificates, & &1.serial_number)
      assert "INT002" in serials
      assert "INT003" in serials
      refute "INT001" in serials
    end

    test "full HTTP flow via router" do
      # OCSP query for active cert
      conn =
        Plug.Test.conn(:post, "/ocsp", %{"serial_number" => "INT001"})
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@router_opts)

      assert conn.status == 200
      assert %{"status" => "good"} = Jason.decode!(conn.resp_body)

      # OCSP query for revoked cert
      conn =
        Plug.Test.conn(:post, "/ocsp", %{"serial_number" => "INT002"})
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@router_opts)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "revoked"
      assert body["reason"] == "key_compromise"

      # CRL endpoint
      conn = Plug.Test.conn(:get, "/crl") |> Router.call(@router_opts)
      assert conn.status == 200
      crl = Jason.decode!(conn.resp_body)
      assert crl["type"] == "X509CRL"
    end
  end

  defp insert_cert(attrs) do
    %CertificateStatus{}
    |> CertificateStatus.changeset(attrs)
    |> Repo.insert!()
  end
end
