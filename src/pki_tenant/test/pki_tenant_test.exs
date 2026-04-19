defmodule PkiTenantTest do
  use ExUnit.Case, async: false

  describe "tenant_id/0" do
    setup do
      original = System.get_env("TENANT_ID")
      on_exit(fn ->
        if original, do: System.put_env("TENANT_ID", original), else: System.delete_env("TENANT_ID")
      end)
      :ok
    end

    test "returns the value of TENANT_ID when set" do
      System.put_env("TENANT_ID", "acme-corp")
      assert PkiTenant.tenant_id() == "acme-corp"
    end

    test "falls back to \"dev\" when TENANT_ID is unset" do
      System.delete_env("TENANT_ID")
      assert PkiTenant.tenant_id() == "dev"
    end
  end
end
