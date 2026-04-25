defmodule PkiTenantWeb.Ca.CustodianPinVaultTest do
  use ExUnit.Case, async: true

  alias PkiTenantWeb.Ca.CustodianPinVault

  describe "store/2 and consume/2" do
    test "consume returns the stored PIN once, then :already_consumed" do
      {:ok, vault} = CustodianPinVault.start_link()

      token = CustodianPinVault.store(vault, "s3cr3t-PIN!")

      assert {:ok, "s3cr3t-PIN!"} = CustodianPinVault.consume(vault, token)
      assert {:error, :already_consumed} = CustodianPinVault.consume(vault, token)

      CustodianPinVault.stop(vault)
    end

    test "double-consume of the same token returns :already_consumed on the second call" do
      {:ok, vault} = CustodianPinVault.start_link()

      token = CustodianPinVault.store(vault, "another-PIN")
      CustodianPinVault.consume(vault, token)

      assert {:error, :already_consumed} = CustodianPinVault.consume(vault, token)

      CustodianPinVault.stop(vault)
    end
  end

  describe "stop/1" do
    test "vault process is no longer alive after stop" do
      {:ok, vault} = CustodianPinVault.start_link()
      assert Process.alive?(vault)

      CustodianPinVault.stop(vault)
      refute Process.alive?(vault)
    end
  end
end
