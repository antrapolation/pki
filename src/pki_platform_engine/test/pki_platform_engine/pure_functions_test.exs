defmodule PkiPlatformEngine.PureFunctionsTest do
  @moduledoc """
  Tests for stateless helper functions that require no database.
  """
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.{PlatformAuth, Plugs.ClearTenantPrefix}
  import Plug.Test, only: [conn: 2]

  # ---------------------------------------------------------------------------
  # PlatformAuth.format_role_label/2
  # ---------------------------------------------------------------------------

  describe "PlatformAuth.format_role_label/2" do
    test "maps CA portal roles" do
      assert PlatformAuth.format_role_label("ca_admin", "ca") == "CA Administrator"
      assert PlatformAuth.format_role_label("key_manager", "ca") == "Key Manager"
      assert PlatformAuth.format_role_label("auditor", "ca") == "Auditor"
    end

    test "maps RA portal roles" do
      assert PlatformAuth.format_role_label("ra_admin", "ra") == "RA Administrator"
      assert PlatformAuth.format_role_label("ra_officer", "ra") == "RA Officer"
      assert PlatformAuth.format_role_label("auditor", "ra") == "Auditor"
    end

    test "maps platform portal roles" do
      assert PlatformAuth.format_role_label("tenant_admin", "platform") == "Tenant Administrator"
    end

    test "falls back to role string for unknown portal/role combo" do
      assert PlatformAuth.format_role_label("superuser", "unknown") == "superuser"
    end
  end

  describe "PlatformAuth.list_users_for_portal/2" do
    test "returns empty list for nil tenant_id" do
      assert PlatformAuth.list_users_for_portal(nil, "ca") == []
    end
  end

  # ---------------------------------------------------------------------------
  # ClearTenantPrefix plug
  # ---------------------------------------------------------------------------

  describe "Plugs.ClearTenantPrefix" do
    test "init/1 returns opts unchanged" do
      assert ClearTenantPrefix.init([]) == []
      assert ClearTenantPrefix.init(key: :val) == [key: :val]
    end

    test "call/2 removes :pki_ecto_prefix from process dictionary" do
      Process.put(:pki_ecto_prefix, "t_abc123_ca")
      conn = conn(:get, "/")
      result_conn = ClearTenantPrefix.call(conn, [])
      assert Process.get(:pki_ecto_prefix) == nil
      assert result_conn == conn
    end

    test "call/2 is a no-op when :pki_ecto_prefix is not set" do
      Process.delete(:pki_ecto_prefix)
      conn = conn(:get, "/")
      result_conn = ClearTenantPrefix.call(conn, [])
      assert result_conn == conn
    end
  end
end
