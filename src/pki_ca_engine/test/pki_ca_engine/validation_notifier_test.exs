defmodule PkiCaEngine.ValidationNotifierTest do
  @moduledoc """
  Tests for the ValidationNotifier module.

  Verifies payload construction, fire-and-forget semantics,
  and graceful handling when validation service is unavailable.
  """
  use ExUnit.Case, async: false

  alias PkiCaEngine.ValidationNotifier

  import ExUnit.CaptureLog

  describe "notify_issuance/1" do
    test "returns :ok when validation_url is nil (skips notification)" do
      original = Application.get_env(:pki_ca_engine, :validation_url)
      Application.put_env(:pki_ca_engine, :validation_url, nil)

      on_exit(fn -> Application.put_env(:pki_ca_engine, :validation_url, original) end)

      cert = build_test_cert()
      assert :ok = ValidationNotifier.notify_issuance(cert)
    end

    test "returns :ok even when HTTP call fails (fire-and-forget)" do
      original = Application.get_env(:pki_ca_engine, :validation_url)
      Application.put_env(:pki_ca_engine, :validation_url, "http://127.0.0.1:1")

      on_exit(fn -> Application.put_env(:pki_ca_engine, :validation_url, original) end)

      cert = build_test_cert()

      log =
        capture_log(fn ->
          assert :ok = ValidationNotifier.notify_issuance(cert)
        end)

      assert log =~ "Failed to notify validation service of issuance"
    end

    test "does not log warnings when validation URL is nil" do
      original = Application.get_env(:pki_ca_engine, :validation_url)
      Application.put_env(:pki_ca_engine, :validation_url, nil)

      on_exit(fn -> Application.put_env(:pki_ca_engine, :validation_url, original) end)

      cert = build_test_cert()

      # Logger level in test config is :warning, so :debug logs are suppressed.
      # Verify no warning-level logs are emitted when URL is nil.
      log = capture_log(fn -> ValidationNotifier.notify_issuance(cert) end)
      assert log == "", "expected no warnings when URL is nil, got: #{inspect(log)}"
    end
  end

  describe "notify_revocation/2" do
    test "returns :ok when validation_url is nil (skips notification)" do
      original = Application.get_env(:pki_ca_engine, :validation_url)
      Application.put_env(:pki_ca_engine, :validation_url, nil)

      on_exit(fn -> Application.put_env(:pki_ca_engine, :validation_url, original) end)

      assert :ok = ValidationNotifier.notify_revocation("serial-123", "key_compromise")
    end

    test "returns :ok even when HTTP call fails (fire-and-forget)" do
      original = Application.get_env(:pki_ca_engine, :validation_url)
      Application.put_env(:pki_ca_engine, :validation_url, "http://127.0.0.1:1")

      on_exit(fn -> Application.put_env(:pki_ca_engine, :validation_url, original) end)

      log =
        capture_log(fn ->
          assert :ok = ValidationNotifier.notify_revocation("serial-456", "superseded")
        end)

      assert log =~ "Failed to notify validation service of revocation"
    end
  end

  describe "error resilience" do
    test "handles non-HTTP errors gracefully" do
      original = Application.get_env(:pki_ca_engine, :validation_url)
      Application.put_env(:pki_ca_engine, :validation_url, "http://256.256.256.256:9999")

      on_exit(fn -> Application.put_env(:pki_ca_engine, :validation_url, original) end)

      cert = build_test_cert()

      # Must not raise
      assert :ok = ValidationNotifier.notify_issuance(cert)
      assert :ok = ValidationNotifier.notify_revocation("serial-err", "unspecified")
    end
  end

  defp build_test_cert do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %{
      serial_number: "test-serial-#{System.unique_integer([:positive])}",
      issuer_key_id: Uniq.UUID.uuid7(),
      subject_dn: "CN=test.example.com,O=Test",
      not_before: now,
      not_after: DateTime.add(now, 365 * 86400, :second)
    }
  end
end
