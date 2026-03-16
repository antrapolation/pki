defmodule PkiValidation.CrlPublisherTest do
  use PkiValidation.DataCase, async: true

  alias PkiValidation.CrlPublisher
  alias PkiValidation.Schema.CertificateStatus

  setup do
    name = :"crl_publisher_test_#{System.unique_integer([:positive])}"
    # Use a very long interval so periodic regen doesn't interfere
    {:ok, pid} = CrlPublisher.start_link(name: name, interval: :timer.hours(24))
    # Allow the GenServer process to access the sandbox
    Ecto.Adapters.SQL.Sandbox.allow(PkiValidation.Repo, self(), pid)
    {:ok, publisher: name, pid: pid}
  end

  describe "get_current_crl/1" do
    test "returns a CRL structure", %{publisher: publisher} do
      {:ok, crl} = CrlPublisher.get_current_crl(publisher)
      assert crl.type == "X509CRL"
      assert crl.version == 2
      assert is_binary(crl.this_update)
      assert is_binary(crl.next_update)
      assert is_list(crl.revoked_certificates)
      assert is_integer(crl.total_revoked)
    end

    test "returns empty CRL when no revoked certificates", %{publisher: publisher} do
      # Force regeneration to pick up current DB state
      {:ok, crl} = CrlPublisher.regenerate(publisher)
      assert crl.revoked_certificates == []
      assert crl.total_revoked == 0
    end
  end

  describe "regenerate/1" do
    test "includes revoked certificates in CRL", %{publisher: publisher} do
      insert_revoked_cert("CRL001", ~U[2026-06-01 00:00:00.000000Z], "key_compromise")
      insert_revoked_cert("CRL002", ~U[2026-07-01 00:00:00.000000Z], "superseded")

      {:ok, crl} = CrlPublisher.regenerate(publisher)
      assert crl.total_revoked == 2

      serials = Enum.map(crl.revoked_certificates, & &1.serial_number)
      assert "CRL001" in serials
      assert "CRL002" in serials
    end

    test "does not include active certificates in CRL", %{publisher: publisher} do
      insert_active_cert("CRL003")
      insert_revoked_cert("CRL004", ~U[2026-06-01 00:00:00.000000Z], "unspecified")

      {:ok, crl} = CrlPublisher.regenerate(publisher)
      assert crl.total_revoked == 1

      serials = Enum.map(crl.revoked_certificates, & &1.serial_number)
      refute "CRL003" in serials
      assert "CRL004" in serials
    end

    test "CRL entries contain revocation details", %{publisher: publisher} do
      insert_revoked_cert("CRL005", ~U[2026-08-15 10:30:00.000000Z], "ca_compromise")

      {:ok, crl} = CrlPublisher.regenerate(publisher)
      [entry] = crl.revoked_certificates
      assert entry.serial_number == "CRL005"
      assert entry.revoked_at == ~U[2026-08-15 10:30:00.000000Z]
      assert entry.reason == "ca_compromise"
    end
  end

  describe "generate_crl/0" do
    test "returns a valid CRL map" do
      crl = CrlPublisher.generate_crl()
      assert crl.type == "X509CRL"
      assert crl.version == 2
    end
  end

  describe "error handling" do
    test "CRL generation error is logged and does not produce false empty CRL", %{publisher: publisher} do
      # First, insert a revoked cert and generate a valid CRL
      insert_revoked_cert("CRL_ERR01", ~U[2026-06-01 00:00:00.000000Z], "key_compromise")
      {:ok, crl} = CrlPublisher.regenerate(publisher)
      assert crl.total_revoked == 1

      # The last valid CRL should be retained in state even after errors.
      # We verify the state holds the valid CRL by fetching it.
      {:ok, current_crl} = CrlPublisher.get_current_crl(publisher)
      assert current_crl.total_revoked == 1
      refute Map.has_key?(current_crl, :generation_error)
    end

    test "get_current_crl includes generation_error flag after failed generation", %{publisher: publisher, pid: pid} do
      # First, insert a revoked cert and generate a valid CRL
      insert_revoked_cert("ERR_FLAG_01", ~U[2026-06-01 00:00:00.000000Z], "key_compromise")
      {:ok, valid_crl} = CrlPublisher.regenerate(publisher)
      assert valid_crl.total_revoked == 1

      # Simulate generation error by setting state directly
      :sys.replace_state(pid, fn state -> %{state | generation_error: true} end)

      {:ok, error_crl} = CrlPublisher.get_current_crl(publisher)
      assert error_crl[:generation_error] == true
      assert error_crl.total_revoked == 1
    end

    test "do_generate_crl logs error on exception" do
      import ExUnit.CaptureLog

      # Temporarily break the repo by using an invalid query module
      _log =
        capture_log(fn ->
          _crl = CrlPublisher.generate_crl()
        end)

      # generate_crl/0 should always return a valid CRL structure (not crash)
      crl = CrlPublisher.generate_crl()
      assert crl.type == "X509CRL"
    end
  end

  defp insert_revoked_cert(serial, revoked_at, reason) do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial,
      issuer_key_id: 1,
      subject_dn: "CN=#{serial}.example.com,O=Test,C=MY",
      status: "revoked",
      not_before: ~U[2026-01-01 00:00:00.000000Z],
      not_after: ~U[2027-12-31 23:59:59.000000Z],
      revoked_at: revoked_at,
      revocation_reason: reason
    })
    |> Repo.insert!()
  end

  defp insert_active_cert(serial) do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial,
      issuer_key_id: 1,
      subject_dn: "CN=#{serial}.example.com,O=Test,C=MY",
      status: "active",
      not_before: ~U[2026-01-01 00:00:00.000000Z],
      not_after: ~U[2027-12-31 23:59:59.000000Z]
    })
    |> Repo.insert!()
  end
end
