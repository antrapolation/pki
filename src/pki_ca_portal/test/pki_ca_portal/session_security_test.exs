defmodule PkiCaPortal.SessionSecurityTest do
  use ExUnit.Case, async: false

  alias PkiCaPortal.SessionSecurity

  describe "notify/2" do
    test "logs audit event for session_hijack_suspected" do
      assert :ok = SessionSecurity.notify(:session_hijack_suspected, %{
        username: "admin",
        role: "ca_admin",
        old_user_agent: "Mozilla/5.0",
        new_user_agent: "curl/7.0",
        ip: "127.0.0.1",
        portal: "ca"
      })
    end

    test "logs audit event for session_ip_changed" do
      assert :ok = SessionSecurity.notify(:session_ip_changed, %{
        username: "admin",
        role: "ca_admin",
        old_ip: "127.0.0.1",
        new_ip: "10.0.0.5",
        portal: "ca"
      })
    end

    test "logs audit event for new_ip_login" do
      assert :ok = SessionSecurity.notify(:new_ip_login, %{
        username: "admin",
        role: "ca_admin",
        ip: "10.0.0.5",
        portal: "ca"
      })
    end

    test "logs audit event for concurrent_sessions" do
      assert :ok = SessionSecurity.notify(:concurrent_sessions, %{
        username: "admin",
        role: "ca_admin",
        session_count: 3,
        portal: "ca"
      })
    end
  end
end
