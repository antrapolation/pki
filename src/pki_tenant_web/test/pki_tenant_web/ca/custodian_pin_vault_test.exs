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

  describe "Process.monitor/1 crash detection" do
    test "DOWN message arrives after vault is killed" do
      # Trap exits so the :kill signal does not propagate to the test process.
      Process.flag(:trap_exit, true)

      {:ok, vault} = CustodianPinVault.start_link()
      ref = Process.monitor(vault)

      Process.exit(vault, :kill)

      assert_receive {:DOWN, ^ref, :process, ^vault, :killed}, 500
    end

    test "stored tokens are inaccessible after vault crash" do
      # Trap exits so the :kill signal does not propagate to the test process.
      Process.flag(:trap_exit, true)

      {:ok, vault} = CustodianPinVault.start_link()
      _token = CustodianPinVault.store(vault, "secret-pin")

      ref = Process.monitor(vault)
      Process.exit(vault, :kill)

      # Confirm the DOWN message arrives (vault is gone)
      assert_receive {:DOWN, ^ref, :process, ^vault, :killed}, 500

      # Any attempt to call the dead vault exits with :noproc
      assert catch_exit(CustodianPinVault.consume(vault, "any-token")) == {:noproc, {GenServer, :call, [vault, {:consume, "any-token"}, 5000]}}
    end
  end
end
