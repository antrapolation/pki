defmodule PkiCaEngine.UserManagementTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.UserManagement
  alias PkiCaEngine.Schema.{CaInstance, CaUser}

  setup do
    {:ok, ca} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "um-test-ca", created_by: "admin"}))

    %{ca: ca}
  end

  # ── create_user/2 ──────────────────────────────────────────────────

  describe "create_user/2" do
    test "creates a user with valid attrs", %{ca: ca} do
      attrs = %{did: "did:example:alice", display_name: "Alice", role: "ca_admin"}
      assert {:ok, %CaUser{} = user} = UserManagement.create_user(ca.id, attrs)
      assert user.did == "did:example:alice"
      assert user.display_name == "Alice"
      assert user.role == "ca_admin"
      assert user.status == "active"
      assert user.ca_instance_id == ca.id
    end

    test "rejects invalid role", %{ca: ca} do
      attrs = %{did: "did:example:bob", display_name: "Bob", role: "superadmin"}
      assert {:error, changeset} = UserManagement.create_user(ca.id, attrs)
      assert %{role: [_]} = errors_on(changeset)
    end

    test "rejects missing required fields", %{ca: ca} do
      assert {:error, changeset} = UserManagement.create_user(ca.id, %{})
      errors = errors_on(changeset)
      assert %{did: ["can't be blank"], role: ["can't be blank"]} = errors
    end

    for role <- ~w(ca_admin key_manager ra_admin auditor) do
      test "accepts valid role #{role}", %{ca: ca} do
        attrs = %{did: "did:example:#{unquote(role)}", role: unquote(role)}
        assert {:ok, %CaUser{role: unquote(role)}} = UserManagement.create_user(ca.id, attrs)
      end
    end
  end

  # ── list_users/1 ───────────────────────────────────────────────────

  describe "list_users/1" do
    test "returns all users for a CA instance", %{ca: ca} do
      {:ok, _} = UserManagement.create_user(ca.id, %{did: "did:u1", role: "ca_admin"})
      {:ok, _} = UserManagement.create_user(ca.id, %{did: "did:u2", role: "auditor"})

      users = UserManagement.list_users(ca.id)
      assert length(users) == 2
    end

    test "returns empty list when no users exist", %{ca: ca} do
      assert UserManagement.list_users(ca.id) == []
    end

    test "filters users by role", %{ca: ca} do
      {:ok, _} = UserManagement.create_user(ca.id, %{did: "did:u1", role: "ca_admin"})
      {:ok, _} = UserManagement.create_user(ca.id, %{did: "did:u2", role: "auditor"})
      {:ok, _} = UserManagement.create_user(ca.id, %{did: "did:u3", role: "ca_admin"})

      users = UserManagement.list_users(ca.id, role: "ca_admin")
      assert length(users) == 2
      assert Enum.all?(users, &(&1.role == "ca_admin"))
    end

    test "does not return users from other CA instances", %{ca: ca} do
      {:ok, other_ca} =
        Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "other-ca", created_by: "admin"}))

      {:ok, _} = UserManagement.create_user(ca.id, %{did: "did:u1", role: "ca_admin"})
      {:ok, _} = UserManagement.create_user(other_ca.id, %{did: "did:u2", role: "auditor"})

      users = UserManagement.list_users(ca.id)
      assert length(users) == 1
    end
  end

  # ── get_user/1 ─────────────────────────────────────────────────────

  describe "get_user/1" do
    test "returns user by ID", %{ca: ca} do
      {:ok, created} = UserManagement.create_user(ca.id, %{did: "did:get:1", role: "ca_admin"})
      assert {:ok, %CaUser{} = user} = UserManagement.get_user(created.id)
      assert user.id == created.id
      assert user.did == "did:get:1"
    end

    test "returns error for non-existent user" do
      assert {:error, :not_found} = UserManagement.get_user(-1)
    end
  end

  # ── update_user/2 ──────────────────────────────────────────────────

  describe "update_user/2" do
    test "updates display_name", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:upd:1", display_name: "Old", role: "ca_admin"})
      assert {:ok, updated} = UserManagement.update_user(user.id, %{display_name: "New"})
      assert updated.display_name == "New"
    end

    test "updates status", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:upd:2", role: "ca_admin"})
      assert {:ok, updated} = UserManagement.update_user(user.id, %{status: "suspended"})
      assert updated.status == "suspended"
    end

    test "does not allow updating role", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:upd:3", role: "ca_admin"})
      assert {:ok, updated} = UserManagement.update_user(user.id, %{role: "auditor"})
      assert updated.role == "ca_admin"
    end

    test "does not allow updating did", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:upd:4", role: "ca_admin"})
      assert {:ok, updated} = UserManagement.update_user(user.id, %{did: "did:changed"})
      assert updated.did == "did:upd:4"
    end

    test "returns error for non-existent user" do
      assert {:error, :not_found} = UserManagement.update_user(-1, %{display_name: "X"})
    end
  end

  # ── delete_user/1 ──────────────────────────────────────────────────

  describe "delete_user/1" do
    test "soft-deletes by setting status to suspended", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:del:1", role: "ca_admin"})
      assert user.status == "active"

      assert {:ok, deleted} = UserManagement.delete_user(user.id)
      assert deleted.status == "suspended"

      # Verify persisted
      assert {:ok, fetched} = UserManagement.get_user(user.id)
      assert fetched.status == "suspended"
    end

    test "returns error for non-existent user" do
      assert {:error, :not_found} = UserManagement.delete_user(-1)
    end
  end

  # ── authorize/2 ────────────────────────────────────────────────────

  describe "authorize/2" do
    test "ca_admin can manage_ca_admins", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:1", role: "ca_admin"})
      assert :ok = UserManagement.authorize(user, :manage_ca_admins)
    end

    test "ca_admin can view_audit_log", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:2", role: "ca_admin"})
      assert :ok = UserManagement.authorize(user, :view_audit_log)
    end

    test "ca_admin cannot manage_keys", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:3", role: "ca_admin"})
      assert {:error, :unauthorized} = UserManagement.authorize(user, :manage_keys)
    end

    test "key_manager can manage_keystores", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:4", role: "key_manager"})
      assert :ok = UserManagement.authorize(user, :manage_keystores)
    end

    test "key_manager cannot view_audit_log", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:5", role: "key_manager"})
      assert {:error, :unauthorized} = UserManagement.authorize(user, :view_audit_log)
    end

    test "ra_admin can manage_ra_admins", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:6", role: "ra_admin"})
      assert :ok = UserManagement.authorize(user, :manage_ra_admins)
    end

    test "ra_admin cannot manage_keys", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:7", role: "ra_admin"})
      assert {:error, :unauthorized} = UserManagement.authorize(user, :manage_keys)
    end

    test "auditor can view_audit_log", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:8", role: "auditor"})
      assert :ok = UserManagement.authorize(user, :view_audit_log)
    end

    test "auditor can participate_ceremony", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:9", role: "auditor"})
      assert :ok = UserManagement.authorize(user, :participate_ceremony)
    end

    test "auditor cannot manage_ca_admins", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:10", role: "auditor"})
      assert {:error, :unauthorized} = UserManagement.authorize(user, :manage_ca_admins)
    end

    test "suspended user is unauthorized", %{ca: ca} do
      {:ok, user} = UserManagement.create_user(ca.id, %{did: "did:auth:11", role: "ca_admin"})
      {:ok, suspended} = UserManagement.delete_user(user.id)
      assert {:error, :unauthorized} = UserManagement.authorize(suspended, :manage_ca_admins)
    end
  end

  # ── Helper ─────────────────────────────────────────────────────────

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
