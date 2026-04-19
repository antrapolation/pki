defmodule PkiCaEngine.KeystoreManagementMnesiaTest do
  @moduledoc "Mnesia-era tests for PkiCaEngine.KeystoreManagement."
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiCaEngine.KeystoreManagement

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  describe "configure_keystore/2" do
    test "creates a software keystore with the canonical provider" do
      assert {:ok, ks} =
               KeystoreManagement.configure_keystore("ca-1", %{type: "software"})

      assert ks.ca_instance_id == "ca-1"
      assert ks.type == "software"
      assert ks.status == "active"
      assert ks.provider_name == "StrapSoftPrivKeyStoreProvider"
      assert ks.config == %{}
    end

    test "accepts a caller-supplied status" do
      {:ok, ks} =
        KeystoreManagement.configure_keystore("ca-1", %{type: "software", status: "inactive"})

      assert ks.status == "inactive"
    end

    test "rejects invalid type" do
      assert {:error, :invalid_type} =
               KeystoreManagement.configure_keystore("ca-1", %{type: "cloud"})
    end

    test "rejects blank ca_instance_id" do
      assert {:error, :ca_instance_required} =
               KeystoreManagement.configure_keystore("", %{type: "software"})

      assert {:error, :ca_instance_required} =
               KeystoreManagement.configure_keystore(nil, %{type: "software"})
    end

    test "HSM keystore without device id defaults to empty config" do
      {:ok, ks} = KeystoreManagement.configure_keystore("ca-1", %{type: "hsm"})
      assert ks.type == "hsm"
      assert ks.config == %{}
      assert ks.provider_name == "StrapSofthsmPrivKeyStoreProvider"
    end
  end

  describe "list_keystores/1" do
    test "filters by ca_instance_id" do
      {:ok, a} = KeystoreManagement.configure_keystore("ca-a", %{type: "software"})
      {:ok, _b} = KeystoreManagement.configure_keystore("ca-b", %{type: "software"})

      ks = KeystoreManagement.list_keystores("ca-a")
      assert length(ks) == 1
      assert hd(ks).id == a.id
    end

    test "returns all when no filter" do
      {:ok, _} = KeystoreManagement.configure_keystore("ca-a", %{type: "software"})
      {:ok, _} = KeystoreManagement.configure_keystore("ca-b", %{type: "software"})

      assert length(KeystoreManagement.list_keystores()) == 2
    end
  end

  describe "available_keystores/1" do
    test "excludes inactive keystores" do
      {:ok, _active} = KeystoreManagement.configure_keystore("ca-a", %{type: "software"})
      {:ok, inactive} =
        KeystoreManagement.configure_keystore("ca-a", %{type: "hsm", status: "inactive"})

      avail = KeystoreManagement.available_keystores("ca-a")
      assert length(avail) == 1
      refute Enum.any?(avail, &(&1.id == inactive.id))
    end
  end

  describe "get_keystore/1" do
    test "returns the record" do
      {:ok, ks} = KeystoreManagement.configure_keystore("ca-a", %{type: "software"})
      assert {:ok, found} = KeystoreManagement.get_keystore(ks.id)
      assert found.id == ks.id
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = KeystoreManagement.get_keystore("nope")
    end
  end

  describe "update_keystore/2" do
    test "flips status" do
      {:ok, ks} = KeystoreManagement.configure_keystore("ca-a", %{type: "software"})
      assert {:ok, u} = KeystoreManagement.update_keystore(ks.id, %{status: "inactive"})
      assert u.status == "inactive"
    end

    test "rejects invalid status" do
      {:ok, ks} = KeystoreManagement.configure_keystore("ca-a", %{type: "software"})

      assert {:error, :invalid_status} =
               KeystoreManagement.update_keystore(ks.id, %{status: "deleted"})
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = KeystoreManagement.update_keystore("nope", %{status: "active"})
    end
  end

  describe "get_provider_module/1" do
    test "maps known types" do
      assert {:ok, "StrapSoftPrivKeyStoreProvider"} =
               KeystoreManagement.get_provider_module("software")

      assert {:ok, "StrapSofthsmPrivKeyStoreProvider"} =
               KeystoreManagement.get_provider_module("hsm")
    end

    test "unknown type returns error" do
      assert {:error, :unknown_provider} = KeystoreManagement.get_provider_module("cloud")
    end
  end
end
