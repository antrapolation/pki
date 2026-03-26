defmodule PkiValidation.OcspResponderTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.OcspResponder
  alias PkiValidation.Schema.CertificateStatus

  @active_cert_attrs %{
    serial_number: "OCSP001",
    issuer_key_id: "019577a0-0000-7000-8000-000000000001",
    subject_dn: "CN=active.example.com,O=Test,C=MY",
    status: "active",
    not_before: ~U[2026-01-01 00:00:00.000000Z],
    not_after: ~U[2027-12-31 23:59:59.000000Z]
  }

  @revoked_cert_attrs %{
    serial_number: "OCSP002",
    issuer_key_id: "019577a0-0000-7000-8000-000000000001",
    subject_dn: "CN=revoked.example.com,O=Test,C=MY",
    status: "revoked",
    not_before: ~U[2026-01-01 00:00:00.000000Z],
    not_after: ~U[2027-12-31 23:59:59.000000Z],
    revoked_at: ~U[2026-06-15 12:00:00.000000Z],
    revocation_reason: "key_compromise"
  }

  @expired_cert_attrs %{
    serial_number: "OCSP003",
    issuer_key_id: "019577a0-0000-7000-8000-000000000001",
    subject_dn: "CN=expired.example.com,O=Test,C=MY",
    status: "active",
    not_before: ~U[2024-01-01 00:00:00.000000Z],
    not_after: ~U[2025-01-01 00:00:00.000000Z]
  }

  describe "check_status_uncached/1" do
    test "returns good for active certificate" do
      insert_cert(@active_cert_attrs)
      assert {:ok, %{status: "good"}} = OcspResponder.check_status_uncached("OCSP001")
    end

    test "returns revoked with details for revoked certificate" do
      insert_cert(@revoked_cert_attrs)

      assert {:ok, response} = OcspResponder.check_status_uncached("OCSP002")
      assert response.status == "revoked"
      assert response.revoked_at == ~U[2026-06-15 12:00:00.000000Z]
      assert response.reason == "key_compromise"
    end

    test "returns unknown for nonexistent certificate" do
      assert {:ok, %{status: "unknown"}} = OcspResponder.check_status_uncached("NONEXISTENT")
    end

    test "returns good for expired active certificate per RFC 6960" do
      insert_cert(@expired_cert_attrs)
      assert {:ok, %{status: "good"}} =
               OcspResponder.check_status_uncached("OCSP003")
    end
  end

  describe "check_status/1 caching behaviour" do
    setup do
      # Invalidate any prior cache entries for our test serials
      PkiValidation.OcspCache.invalidate("UNKNOWN_SERIAL_CACHE")
      PkiValidation.OcspCache.invalidate("OCSP_CACHE_GOOD")
      PkiValidation.OcspCache.invalidate("OCSP_CACHE_REVOKED")
      :ok
    end

    test "does not cache unknown responses" do
      # No cert inserted, so serial is unknown
      {:ok, %{status: "unknown"}} = OcspResponder.check_status("UNKNOWN_SERIAL_CACHE")

      # Cache should have a miss for this serial — unknown was not cached
      assert :miss == PkiValidation.OcspCache.get("UNKNOWN_SERIAL_CACHE")
    end

    test "caches good responses" do
      insert_cert(%{@active_cert_attrs | serial_number: "OCSP_CACHE_GOOD"})

      {:ok, %{status: "good"}} = OcspResponder.check_status("OCSP_CACHE_GOOD")

      # Should be cached now
      assert {:ok, %{status: "good"}} = PkiValidation.OcspCache.get("OCSP_CACHE_GOOD")
    end

    test "caches revoked responses" do
      insert_cert(%{@revoked_cert_attrs | serial_number: "OCSP_CACHE_REVOKED"})

      {:ok, %{status: "revoked"}} = OcspResponder.check_status("OCSP_CACHE_REVOKED")

      assert {:ok, %{status: "revoked"}} = PkiValidation.OcspCache.get("OCSP_CACHE_REVOKED")
    end
  end

  defp insert_cert(attrs) do
    %CertificateStatus{}
    |> CertificateStatus.changeset(attrs)
    |> Repo.insert!()
  end
end
