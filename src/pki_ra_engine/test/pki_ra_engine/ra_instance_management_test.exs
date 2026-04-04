defmodule PkiRaEngine.RaInstanceManagementTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.RaInstanceManagement

  @valid_attrs %{name: "JPJ Registration Authority", created_by: "admin"}

  describe "create_ra_instance/1" do
    test "creates an RA instance with valid attrs" do
      assert {:ok, ra} = RaInstanceManagement.create_ra_instance(nil,@valid_attrs)
      assert ra.name == "JPJ Registration Authority"
      assert ra.status == "initialized"
      assert ra.created_by == "admin"
      assert ra.id != nil
    end

    test "rejects duplicate name" do
      assert {:ok, _} = RaInstanceManagement.create_ra_instance(nil,@valid_attrs)
      assert {:error, changeset} = RaInstanceManagement.create_ra_instance(nil,@valid_attrs)
      assert errors_on(changeset)[:name]
    end

    test "rejects missing name" do
      assert {:error, changeset} = RaInstanceManagement.create_ra_instance(nil,%{created_by: "admin"})
      assert errors_on(changeset)[:name]
    end
  end

  describe "list_ra_instances/0" do
    test "returns empty list when no instances" do
      assert RaInstanceManagement.list_ra_instances(nil) == []
    end

    test "returns all created instances" do
      {:ok, _} = RaInstanceManagement.create_ra_instance(nil,%{name: "RA-1", created_by: "admin"})
      {:ok, _} = RaInstanceManagement.create_ra_instance(nil,%{name: "RA-2", created_by: "admin"})
      assert length(RaInstanceManagement.list_ra_instances(nil)) == 2
    end
  end

  describe "get_ra_instance/1" do
    test "returns instance by id" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(nil,@valid_attrs)
      assert {:ok, found} = RaInstanceManagement.get_ra_instance(nil,ra.id)
      assert found.id == ra.id
      assert found.name == ra.name
    end

    test "returns error for non-existent id" do
      assert {:error, :not_found} = RaInstanceManagement.get_ra_instance(nil,Uniq.UUID.uuid7())
    end
  end

  describe "update_status/2" do
    test "updates status to active" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(nil,@valid_attrs)
      assert {:ok, updated} = RaInstanceManagement.update_status(nil,ra.id, "active")
      assert updated.status == "active"
    end

    test "updates status to suspended" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(nil,@valid_attrs)
      assert {:ok, updated} = RaInstanceManagement.update_status(nil,ra.id, "suspended")
      assert updated.status == "suspended"
    end

    test "rejects invalid status" do
      {:ok, ra} = RaInstanceManagement.create_ra_instance(nil,@valid_attrs)
      assert {:error, changeset} = RaInstanceManagement.update_status(nil,ra.id, "deleted")
      assert errors_on(changeset)[:status]
    end

    test "returns error for non-existent id" do
      assert {:error, :not_found} = RaInstanceManagement.update_status(nil,Uniq.UUID.uuid7(), "active")
    end
  end
end
