defmodule PkiValidation.E2ETest do
  @moduledoc """
  End-to-end tests simulating CA -> Validation data flow.

  Since there's no real-time sync between CA and Validation yet, these tests
  simulate the sync by directly inserting certificate_status records (as if
  synced from CA) and then verifying the validation services respond correctly.
  """
  use PkiValidation.DataCase, async: false

  alias PkiValidation.Api.Router
  alias PkiValidation.CrlPublisher
  alias PkiValidation.OcspResponder
  alias PkiValidation.Schema.CertificateStatus

  @router_opts Router.init([])

  describe "full certificate lifecycle through validation" do
    test "new active cert -> OCSP good -> revoke -> OCSP revoked -> CRL includes serial" do
      serial = "E2E_CERT_001"

      # Step 1: Certificate issued - sync active cert to validation
      insert_cert(%{
        serial_number: serial,
        issuer_key_id: "019577a0-0000-7000-8000-000000000001",
        subject_dn: "CN=e2e-test.example.com,O=Test,C=MY",
        status: "active",
        not_before: ~U[2026-01-01 00:00:00.000000Z],
        not_after: ~U[2027-12-31 23:59:59.000000Z]
      })

      # Step 2: OCSP check - should return "good"
      {:ok, response} = OcspResponder.check_status_uncached(serial)
      assert response.status == "good"

      # Step 3: CRL should NOT include this serial
      crl = CrlPublisher.generate_crl()
      refute Enum.any?(crl.revoked_certificates, fn rc -> rc.serial_number == serial end)

      # Step 4: Certificate revoked - update status in validation DB
      cert = Repo.get_by!(CertificateStatus, serial_number: serial)

      {:ok, _} =
        cert
        |> Ecto.Changeset.change(%{
          status: "revoked",
          revoked_at: ~U[2026-06-15 00:00:00.000000Z],
          revocation_reason: "key_compromise"
        })
        |> Repo.update()

      # Step 5: Invalidate OCSP cache for this serial
      PkiValidation.OcspCache.invalidate(serial)

      # Step 6: OCSP check - should return "revoked"
      {:ok, revoked_response} = OcspResponder.check_status_uncached(serial)
      assert revoked_response.status == "revoked"
      assert revoked_response.reason == "key_compromise"

      # Step 7: CRL should include this serial
      updated_crl = CrlPublisher.generate_crl()
      assert Enum.any?(updated_crl.revoked_certificates, fn rc -> rc.serial_number == serial end)
    end

    test "expired cert returns good (not unknown) per RFC 6960" do
      serial = "E2E_EXPIRED_001"

      insert_cert(%{
        serial_number: serial,
        issuer_key_id: "019577a0-0000-7000-8000-000000000001",
        subject_dn: "CN=expired.example.com,O=Test,C=MY",
        status: "active",
        not_before: ~U[2024-01-01 00:00:00.000000Z],
        not_after: ~U[2025-01-01 00:00:00.000000Z]
      })

      {:ok, response} = OcspResponder.check_status_uncached(serial)
      # expired but not revoked = good per RFC 6960
      assert response.status == "good"
    end

    test "unknown cert -> OCSP unknown, then insert -> OCSP good (unknown not cached)" do
      serial = "E2E_LATE_ARRIVAL_001"

      # No cert exists yet - should be unknown
      {:ok, response1} = OcspResponder.check_status(serial)
      assert response1.status == "unknown"

      # Insert the cert now (simulating late sync from CA)
      insert_cert(%{
        serial_number: serial,
        issuer_key_id: "019577a0-0000-7000-8000-000000000001",
        subject_dn: "CN=late-arrival.example.com,O=Test,C=MY",
        status: "active",
        not_before: ~U[2026-01-01 00:00:00.000000Z],
        not_after: ~U[2027-12-31 23:59:59.000000Z]
      })

      # Should return "good" now (unknown was not cached)
      {:ok, response2} = OcspResponder.check_status(serial)
      assert response2.status == "good"
    end

    test "multiple revocations appear in CRL" do
      for i <- 1..5 do
        serial = "E2E_MULTI_#{String.pad_leading("#{i}", 3, "0")}"

        insert_cert(%{
          serial_number: serial,
          issuer_key_id: "019577a0-0000-7000-8000-000000000001",
          subject_dn: "CN=multi-#{i}.example.com,O=Test,C=MY",
          status: "revoked",
          not_before: ~U[2026-01-01 00:00:00.000000Z],
          not_after: ~U[2027-12-31 23:59:59.000000Z],
          revoked_at: ~U[2026-06-01 00:00:00.000000Z],
          revocation_reason: "cessation_of_operation"
        })
      end

      crl = CrlPublisher.generate_crl()
      assert crl.total_revoked >= 5

      for i <- 1..5 do
        serial = "E2E_MULTI_#{String.pad_leading("#{i}", 3, "0")}"
        assert Enum.any?(crl.revoked_certificates, fn rc -> rc.serial_number == serial end)
      end
    end
  end

  describe "HTTP endpoint E2E" do
    test "POST /ocsp -> good -> revoke -> POST /ocsp -> revoked, GET /crl includes serial" do
      serial = "HTTP_E2E_001"

      insert_cert(%{
        serial_number: serial,
        issuer_key_id: "019577a0-0000-7000-8000-000000000001",
        subject_dn: "CN=http-e2e.example.com,O=Test,C=MY",
        status: "active",
        not_before: ~U[2026-01-01 00:00:00.000000Z],
        not_after: ~U[2027-12-31 23:59:59.000000Z]
      })

      # OCSP via HTTP - should be good
      conn =
        Plug.Test.conn(:post, "/ocsp", %{"serial_number" => serial})
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@router_opts)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "good"

      # Revoke the certificate
      cert = Repo.get_by!(CertificateStatus, serial_number: serial)

      cert
      |> Ecto.Changeset.change(%{
        status: "revoked",
        revoked_at: ~U[2026-06-15 00:00:00.000000Z],
        revocation_reason: "key_compromise"
      })
      |> Repo.update!()

      PkiValidation.OcspCache.invalidate(serial)

      # OCSP again via HTTP - should be revoked
      conn2 =
        Plug.Test.conn(:post, "/ocsp", %{"serial_number" => serial})
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Router.call(@router_opts)

      assert conn2.status == 200
      body2 = Jason.decode!(conn2.resp_body)
      assert body2["status"] == "revoked"

      # CRL verification - generate_crl/0 queries the DB directly (the HTTP
      # /crl endpoint serves the GenServer's cached CRL which is not sandbox-aware
      # in tests, so we verify the data layer directly like the existing integration tests)
      crl = CrlPublisher.generate_crl()

      assert Enum.any?(crl.revoked_certificates, fn rc ->
               rc.serial_number == serial
             end)

      # Also verify the HTTP /crl endpoint is reachable
      crl_conn = Plug.Test.conn(:get, "/crl") |> Router.call(@router_opts)
      assert crl_conn.status == 200
      crl_body = Jason.decode!(crl_conn.resp_body)
      assert crl_body["type"] == "X509CRL"
    end
  end

  defp insert_cert(attrs) do
    %CertificateStatus{}
    |> CertificateStatus.changeset(attrs)
    |> Repo.insert!()
  end
end
