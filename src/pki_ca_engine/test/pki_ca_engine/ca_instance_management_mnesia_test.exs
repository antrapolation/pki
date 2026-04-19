defmodule PkiCaEngine.CaInstanceManagementMnesiaTest do
  @moduledoc """
  Mnesia-era tests for `CaInstanceManagement` covering the rename +
  status-update additions used by the ported tenant_web
  ca_instances_live.
  """
  use ExUnit.Case, async: false

  alias PkiCaEngine.CaInstanceManagement
  alias PkiMnesia.TestHelper

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  defp insert_instance(attrs \\ %{}) do
    defaults = %{
      name: "CA-#{System.unique_integer([:positive])}",
      is_root: true,
      status: "active"
    }

    {:ok, instance} =
      CaInstanceManagement.create_ca_instance(Map.merge(defaults, attrs))

    instance
  end

  describe "update_name/2" do
    test "renames an existing instance" do
      ca = insert_instance(%{name: "old name"})

      assert {:ok, updated} = CaInstanceManagement.update_name(ca.id, "new name")
      assert updated.name == "new name"
      assert updated.id == ca.id
    end

    test "trims whitespace around the name" do
      ca = insert_instance()

      assert {:ok, updated} = CaInstanceManagement.update_name(ca.id, "   Padded Name   ")
      assert updated.name == "Padded Name"
    end

    test "rejects empty or whitespace-only names" do
      ca = insert_instance()

      assert {:error, :empty_name} = CaInstanceManagement.update_name(ca.id, "")
      assert {:error, :empty_name} = CaInstanceManagement.update_name(ca.id, "    ")
      assert {:error, :empty_name} = CaInstanceManagement.update_name(ca.id, nil)
    end

    test "returns :not_found for unknown id" do
      assert {:error, :not_found} = CaInstanceManagement.update_name("nonexistent", "Whatever")
    end
  end

  describe "update_status/2" do
    test "sets status to active" do
      ca = insert_instance(%{status: "suspended"})

      assert {:ok, updated} = CaInstanceManagement.update_status(ca.id, "active")
      assert updated.status == "active"
    end

    test "sets status to suspended" do
      ca = insert_instance()

      assert {:ok, updated} = CaInstanceManagement.update_status(ca.id, "suspended")
      assert updated.status == "suspended"
    end

    test "sets status to inactive" do
      ca = insert_instance()

      assert {:ok, updated} = CaInstanceManagement.update_status(ca.id, "inactive")
      assert updated.status == "inactive"
    end

    test "rejects unknown status values" do
      ca = insert_instance()

      assert {:error, :invalid_status} = CaInstanceManagement.update_status(ca.id, "bogus")
      assert {:error, :invalid_status} = CaInstanceManagement.update_status(ca.id, "Active")
    end

    test "returns :not_found for unknown id" do
      assert {:error, :not_found} = CaInstanceManagement.update_status("nonexistent", "active")
    end

    test "does NOT cascade status change to children (documented behavior)" do
      # parent and child
      root = insert_instance(%{name: "root", is_root: true})
      child = insert_instance(%{name: "child", parent_id: root.id, is_root: false})

      assert {:ok, _} = CaInstanceManagement.update_status(root.id, "suspended")

      {:ok, refreshed_child} = CaInstanceManagement.get_ca_instance(child.id)
      assert refreshed_child.status == "active",
             "child status should not auto-cascade until the cascade TODO is implemented"
    end
  end
end
