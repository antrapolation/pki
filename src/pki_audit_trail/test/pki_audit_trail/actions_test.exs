defmodule PkiAuditTrail.ActionsTest do
  use ExUnit.Case, async: true
  alias PkiAuditTrail.Actions

  test "all actions are strings" do
    for action <- Actions.all(), do: assert is_binary(action)
  end

  test "contains expected actions from spec" do
    expected = [
      "ceremony_started", "ceremony_completed",
      "key_generated", "key_activated", "key_suspended",
      "csr_submitted", "csr_verified", "csr_approved", "csr_rejected",
      "certificate_issued", "certificate_revoked",
      "user_created", "user_updated", "user_deleted",
      "keystore_configured",
      "keypair_access_granted", "keypair_access_revoked",
      "login", "logout"
    ]
    for action <- expected, do: assert action in Actions.all(), "Missing action: #{action}"
  end

  test "valid?/1 returns true for known actions" do
    assert Actions.valid?("login")
    assert Actions.valid?("certificate_issued")
  end

  test "valid?/1 returns false for unknown actions" do
    refute Actions.valid?("unknown_action")
  end
end
