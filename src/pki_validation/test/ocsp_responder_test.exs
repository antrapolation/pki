defmodule PkiValidation.OcspResponderTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.CertificateStatus
  alias PkiValidation.OcspResponder

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "check_status returns unknown for non-existent serial" do
    {:ok, response} = OcspResponder.check_status("nonexistent-serial")
    assert response.status == "unknown"
  end

  test "check_status returns good for active certificate not yet expired" do
    cs = CertificateStatus.new(%{
      serial_number: "abc123",
      issuer_key_id: "key-1",
      status: "active",
      not_after: DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)
    })
    {:ok, _} = Repo.insert(cs)

    {:ok, response} = OcspResponder.check_status("abc123")
    assert response.status == "good"
    assert response.serial_number == "abc123"
    assert %DateTime{} = response.not_after
  end

  test "check_status returns revoked for revoked certificate" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    cs = CertificateStatus.new(%{
      serial_number: "revoked123",
      issuer_key_id: "key-1",
      status: "revoked",
      revoked_at: now,
      revocation_reason: "keyCompromise"
    })
    {:ok, _} = Repo.insert(cs)

    {:ok, response} = OcspResponder.check_status("revoked123")
    assert response.status == "revoked"
    assert response.reason == "keyCompromise"
    assert response.serial_number == "revoked123"
    assert %DateTime{} = response.revoked_at
  end

  test "check_status returns revoked for expired certificate" do
    cs = CertificateStatus.new(%{
      serial_number: "expired123",
      issuer_key_id: "key-1",
      status: "active",
      not_after: DateTime.utc_now() |> DateTime.add(-86400, :second) |> DateTime.truncate(:second)
    })
    {:ok, _} = Repo.insert(cs)

    {:ok, response} = OcspResponder.check_status("expired123")
    assert response.status == "revoked"
    assert response.reason == "certificate_expired"
    assert response.serial_number == "expired123"
  end

  test "check_status handles active cert with no not_after (never expires)" do
    cs = CertificateStatus.new(%{
      serial_number: "no-expiry",
      issuer_key_id: "key-1",
      status: "active",
      not_after: nil
    })
    {:ok, _} = Repo.insert(cs)

    {:ok, response} = OcspResponder.check_status("no-expiry")
    assert response.status == "good"
  end

  test "signed_response returns :try_later when key not active (fail-closed, RFC 6960 §2.3)" do
    # E3.1: signed_response is now fail-closed — when no active lease exists it
    # returns {:ok, %{status: :try_later}} instead of an unsigned response.
    {:ok, ka} = PkiCaEngine.KeyActivation.start_link(name: :test_ka_ocsp)

    on_exit(fn ->
      if Process.alive?(ka), do: GenServer.stop(ka)
    end)

    cs = CertificateStatus.new(%{
      serial_number: "sign-test",
      issuer_key_id: "key-sign-1",
      status: "active",
      not_after: DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)
    })
    {:ok, _} = Repo.insert(cs)

    {:ok, response} = OcspResponder.signed_response("sign-test", "key-sign-1",
      activation_server: :test_ka_ocsp)

    assert response.status == :try_later
    assert response.reason == :no_active_lease
  end
end
