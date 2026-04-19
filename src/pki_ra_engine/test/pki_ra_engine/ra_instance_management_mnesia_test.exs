defmodule PkiRaEngine.RaInstanceManagementMnesiaTest do
  @moduledoc "Mnesia-era tests for PkiRaEngine.RaInstanceManagement."
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiRaEngine.RaInstanceManagement

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  describe "create_ra_instance/1" do
    test "creates an instance with a name" do
      assert {:ok, ra} = RaInstanceManagement.create_ra_instance(%{name: "RA-A"})
      assert ra.name == "RA-A"
      assert ra.status == "active"
      assert is_binary(ra.id)
    end

    test "trims whitespace around the name" do
      assert {:ok, ra} = RaInstanceManagement.create_ra_instance(%{name: "   Padded   "})
      assert ra.name == "Padded"
    end

    test "rejects missing or blank name" do
      assert {:error, :name_required} = RaInstanceManagement.create_ra_instance(%{})
      assert {:error, :name_required} = RaInstanceManagement.create_ra_instance(%{name: ""})
      assert {:error, :name_required} = RaInstanceManagement.create_ra_instance(%{name: "   "})
    end
  end

  describe "get_ra_instance/1" do
    test "returns the instance" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(%{name: "RA-Get"})
      assert {:ok, found} = RaInstanceManagement.get_ra_instance(ra.id)
      assert found.id == ra.id
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = RaInstanceManagement.get_ra_instance("nope")
    end
  end

  describe "list_ra_instances/0" do
    test "lists every instance" do
      {:ok, _} = RaInstanceManagement.create_ra_instance(%{name: "RA-1"})
      {:ok, _} = RaInstanceManagement.create_ra_instance(%{name: "RA-2"})
      assert length(RaInstanceManagement.list_ra_instances()) == 2
    end

    test "empty when none exist" do
      assert RaInstanceManagement.list_ra_instances() == []
    end
  end

  describe "update_status/2" do
    test "updates to active / suspended / inactive" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(%{name: "RA-Status"})
      assert {:ok, r1} = RaInstanceManagement.update_status(ra.id, "suspended")
      assert r1.status == "suspended"
      assert {:ok, r2} = RaInstanceManagement.update_status(ra.id, "inactive")
      assert r2.status == "inactive"
      assert {:ok, r3} = RaInstanceManagement.update_status(ra.id, "active")
      assert r3.status == "active"
    end

    test "rejects invalid status" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(%{name: "RA-Bad"})
      assert {:error, :invalid_status} = RaInstanceManagement.update_status(ra.id, "deleted")
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = RaInstanceManagement.update_status("nope", "active")
    end
  end
end
