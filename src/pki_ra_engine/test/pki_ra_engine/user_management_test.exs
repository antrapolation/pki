defmodule PkiRaEngine.UserManagementTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.UserManagement

  @valid_attrs %{
    display_name: "Alice Admin",
    role: "ra_admin"
  }

  defp create_user!(attrs \\ %{}) do
    {:ok, user} = UserManagement.create_user(Map.merge(@valid_attrs, attrs))
    user
  end

  describe "create_user/1" do
    test "creates user with valid attrs" do
      assert {:ok, user} = UserManagement.create_user(@valid_attrs)
      assert user.display_name == "Alice Admin"
      assert user.role == "ra_admin"
      assert user.status == "active"
    end

    test "fails with missing required fields" do
      assert {:error, changeset} = UserManagement.create_user(%{})
      assert errors_on(changeset)[:role]
    end

    test "fails with invalid role" do
      assert {:error, changeset} = UserManagement.create_user(%{@valid_attrs | role: "superadmin"})
      assert errors_on(changeset)[:role]
    end

  end

  describe "list_users/1" do
    test "lists all users with no filters" do
      create_user!(%{role: "ra_admin"})
      create_user!(%{role: "ra_officer"})

      users = UserManagement.list_users([])
      assert length(users) == 2
    end

    test "filters by role" do
      create_user!(%{role: "ra_admin"})
      create_user!(%{role: "ra_officer"})

      users = UserManagement.list_users(role: "ra_admin")
      assert length(users) == 1
      assert hd(users).role == "ra_admin"
    end

    test "filters by status" do
      user = create_user!()
      create_user!()
      UserManagement.delete_user(user.id)

      users = UserManagement.list_users(status: "suspended")
      assert length(users) == 1
      assert hd(users).status == "suspended"
    end
  end

  describe "get_user/1" do
    test "returns user by id" do
      user = create_user!()
      assert {:ok, found} = UserManagement.get_user(user.id)
      assert found.id == user.id
    end

    test "returns error for non-existent id" do
      assert {:error, :not_found} = UserManagement.get_user(Uniq.UUID.uuid7())
    end
  end

  describe "update_user/2" do
    test "updates display_name" do
      user = create_user!()
      assert {:ok, updated} = UserManagement.update_user(user.id, %{display_name: "Bob"})
      assert updated.display_name == "Bob"
    end

    test "updates status" do
      user = create_user!()
      assert {:ok, updated} = UserManagement.update_user(user.id, %{status: "suspended"})
      assert updated.status == "suspended"
    end

    test "cannot update role" do
      user = create_user!()
      assert {:ok, updated} = UserManagement.update_user(user.id, %{role: "auditor"})
      assert updated.role == "ra_admin"
    end

    test "returns error for non-existent user" do
      assert {:error, :not_found} = UserManagement.update_user(Uniq.UUID.uuid7(), %{display_name: "X"})
    end
  end

  describe "delete_user/1" do
    test "soft-deletes by setting status to suspended" do
      user = create_user!()
      assert {:ok, deleted} = UserManagement.delete_user(user.id)
      assert deleted.status == "suspended"
    end

    test "returns error for non-existent user" do
      assert {:error, :not_found} = UserManagement.delete_user(Uniq.UUID.uuid7())
    end
  end

  describe "authorize/2" do
    test "ra_admin has manage permissions" do
      assert :ok = UserManagement.authorize("ra_admin", :manage_ra_admins)
      assert :ok = UserManagement.authorize("ra_admin", :manage_ra_officers)
      assert :ok = UserManagement.authorize("ra_admin", :manage_cert_profiles)
      assert :ok = UserManagement.authorize("ra_admin", :manage_service_configs)
      assert :ok = UserManagement.authorize("ra_admin", :manage_api_keys)
    end

    test "ra_officer has csr permissions" do
      assert :ok = UserManagement.authorize("ra_officer", :process_csrs)
      assert :ok = UserManagement.authorize("ra_officer", :view_csrs)
    end

    test "auditor has audit permissions" do
      assert :ok = UserManagement.authorize("auditor", :view_audit_log)
    end

    test "ra_officer cannot manage admins" do
      assert {:error, :unauthorized} = UserManagement.authorize("ra_officer", :manage_ra_admins)
    end

    test "auditor cannot process csrs" do
      assert {:error, :unauthorized} = UserManagement.authorize("auditor", :process_csrs)
    end

    test "unknown role is unauthorized" do
      assert {:error, :unauthorized} = UserManagement.authorize("unknown", :view_audit_log)
    end
  end
end
