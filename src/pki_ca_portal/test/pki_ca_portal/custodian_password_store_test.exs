defmodule PkiCaPortal.CustodianPasswordStoreTest do
  use ExUnit.Case, async: false

  alias PkiCaPortal.CustodianPasswordStore

  setup do
    CustodianPasswordStore.clear_all()
    :ok
  end

  describe "store_password/3 and get_password/2" do
    test "stores and retrieves a password" do
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-1", "secret123")
      assert {:ok, "secret123"} = CustodianPasswordStore.get_password("ceremony-1", "user-1")
    end
  end

  describe "get_password/2" do
    test "returns error for missing password" do
      assert {:error, :not_found} = CustodianPasswordStore.get_password("no", "no")
    end
  end

  describe "get_all_passwords/1" do
    test "returns all passwords for a ceremony" do
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-1", "pass1")
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-2", "pass2")
      :ok = CustodianPasswordStore.store_password("ceremony-2", "user-3", "pass3")

      passwords = CustodianPasswordStore.get_all_passwords("ceremony-1")
      assert length(passwords) == 2
      assert {"user-1", "pass1"} in passwords
      assert {"user-2", "pass2"} in passwords
    end
  end

  describe "wipe_ceremony/1" do
    test "removes all passwords for a ceremony" do
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-1", "pass1")
      :ok = CustodianPasswordStore.store_password("ceremony-1", "user-2", "pass2")
      :ok = CustodianPasswordStore.wipe_ceremony("ceremony-1")
      assert {:error, :not_found} = CustodianPasswordStore.get_password("ceremony-1", "user-1")
      assert {:error, :not_found} = CustodianPasswordStore.get_password("ceremony-1", "user-2")
    end
  end

  describe "has_all_passwords?/2" do
    test "returns true when all users have submitted" do
      :ok = CustodianPasswordStore.store_password("c1", "u1", "p1")
      :ok = CustodianPasswordStore.store_password("c1", "u2", "p2")
      assert CustodianPasswordStore.has_all_passwords?("c1", ["u1", "u2"])
    end

    test "returns false when some users are missing" do
      :ok = CustodianPasswordStore.store_password("c1", "u1", "p1")
      refute CustodianPasswordStore.has_all_passwords?("c1", ["u1", "u2"])
    end
  end
end
