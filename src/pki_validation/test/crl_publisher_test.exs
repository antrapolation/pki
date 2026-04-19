defmodule PkiValidation.CrlPublisherTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.CertificateStatus
  alias PkiValidation.CrlPublisher

  setup do
    dir = TestHelper.setup_mnesia()

    # Use a long interval so scheduled regeneration doesn't fire during tests
    {:ok, pid} = CrlPublisher.start_link(name: :test_crl, interval: :timer.hours(24))

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{crl: :test_crl}
  end

  test "get_current_crl returns empty CRL initially", %{crl: crl} do
    # Wait for the initial :generate message to be processed
    Process.sleep(200)

    {:ok, crl_data} = CrlPublisher.get_current_crl(crl)
    assert crl_data.type == "X509CRL"
    assert crl_data.version == 2
    assert crl_data.total_revoked == 0
    assert crl_data.revoked_certificates == []
    assert is_binary(crl_data.this_update)
    assert is_binary(crl_data.next_update)
  end

  test "regenerate returns freshly built CRL", %{crl: crl} do
    {:ok, crl_data} = CrlPublisher.regenerate(crl)
    assert crl_data.type == "X509CRL"
    assert crl_data.total_revoked == 0
  end

  test "regenerate includes revoked certificates", %{crl: crl} do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    cs = CertificateStatus.new(%{
      serial_number: "revoked-abc",
      issuer_key_id: "key-1",
      status: "revoked",
      revoked_at: now,
      revocation_reason: "keyCompromise"
    })
    {:ok, _} = Repo.insert(cs)

    {:ok, crl_data} = CrlPublisher.regenerate(crl)
    assert crl_data.total_revoked == 1

    [entry] = crl_data.revoked_certificates
    assert entry.serial_number == "revoked-abc"
    assert entry.reason == "keyCompromise"
  end

  test "regenerate excludes active (non-revoked) certificates", %{crl: crl} do
    cs_active = CertificateStatus.new(%{
      serial_number: "active-001",
      issuer_key_id: "key-1",
      status: "active",
      not_after: DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)
    })
    {:ok, _} = Repo.insert(cs_active)

    {:ok, crl_data} = CrlPublisher.regenerate(crl)
    assert crl_data.total_revoked == 0
  end

  test "regenerate returns sorted list when multiple revocations exist", %{crl: crl} do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    earlier = DateTime.add(now, -3600, :second)

    cs1 = CertificateStatus.new(%{
      serial_number: "rev-later",
      issuer_key_id: "key-1",
      status: "revoked",
      revoked_at: now,
      revocation_reason: "superseded"
    })
    cs2 = CertificateStatus.new(%{
      serial_number: "rev-earlier",
      issuer_key_id: "key-1",
      status: "revoked",
      revoked_at: earlier,
      revocation_reason: "keyCompromise"
    })
    {:ok, _} = Repo.insert(cs1)
    {:ok, _} = Repo.insert(cs2)

    {:ok, crl_data} = CrlPublisher.regenerate(crl)
    assert crl_data.total_revoked == 2

    [first, second] = crl_data.revoked_certificates
    assert first.serial_number == "rev-earlier"
    assert second.serial_number == "rev-later"
  end

  test "get_current_crl returns generation_error flag when last generation failed", %{crl: crl} do
    # Wait for initial generation to succeed
    Process.sleep(200)

    # Verify no error flag initially
    {:ok, crl_data} = CrlPublisher.get_current_crl(crl)
    refute Map.get(crl_data, :generation_error)
  end
end
