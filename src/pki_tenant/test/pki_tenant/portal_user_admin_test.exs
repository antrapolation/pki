defmodule PkiTenant.PortalUserAdminTest do
  @moduledoc "Mnesia-era tests for PkiTenant.PortalUserAdmin."
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiTenant.PortalUserAdmin

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  defp valid_attrs(overrides \\ %{}) do
    Map.merge(
      %{
        username: "alice#{System.unique_integer([:positive])}",
        display_name: "Alice",
        email: "alice@example.com",
        role: "ca_admin"
      },
      overrides
    )
  end

  describe "create_user/1" do
    test "creates a user and returns plaintext password" do
      assert {:ok, user, plaintext} = PortalUserAdmin.create_user(valid_attrs())
      assert is_binary(plaintext)
      assert String.length(plaintext) == 16
      assert user.status == "active"
      assert user.role == "ca_admin"
      assert String.starts_with?(user.password_hash, "$argon2")
    end

    test "stores email lowercased and trimmed" do
      {:ok, user, _pw} =
        PortalUserAdmin.create_user(valid_attrs(%{email: "  Alice@Example.COM  "}))

      assert user.email == "alice@example.com"
    end

    test "rejects duplicate usernames" do
      {:ok, _, _} = PortalUserAdmin.create_user(valid_attrs(%{username: "dup"}))

      assert {:error, :username_taken} =
               PortalUserAdmin.create_user(valid_attrs(%{username: "dup"}))
    end

    test "rejects invalid role" do
      assert {:error, :invalid_role} =
               PortalUserAdmin.create_user(valid_attrs(%{role: "platform_admin"}))
    end

    test "rejects invalid username characters" do
      assert {:error, :invalid_username} =
               PortalUserAdmin.create_user(valid_attrs(%{username: "ali ce"}))
    end

    test "rejects invalid email" do
      assert {:error, :invalid_email} =
               PortalUserAdmin.create_user(valid_attrs(%{email: "not-an-email"}))
    end

    test "rejects blank display_name" do
      assert {:error, :invalid_display_name} =
               PortalUserAdmin.create_user(valid_attrs(%{display_name: ""}))
    end
  end

  describe "list_users/1" do
    test "returns only roles belonging to the scope" do
      {:ok, _, _} = PortalUserAdmin.create_user(valid_attrs(%{username: "ca1", role: "ca_admin"}))
      {:ok, _, _} = PortalUserAdmin.create_user(valid_attrs(%{username: "km1", role: "key_manager"}))
      {:ok, _, _} = PortalUserAdmin.create_user(valid_attrs(%{username: "ra1", role: "ra_admin"}))
      {:ok, _, _} = PortalUserAdmin.create_user(valid_attrs(%{username: "ro1", role: "ra_officer"}))
      {:ok, _, _} = PortalUserAdmin.create_user(valid_attrs(%{username: "aud1", role: "auditor"}))

      ca_names = PortalUserAdmin.list_users(:ca) |> Enum.map(& &1.username)
      assert Enum.sort(ca_names) == ~w(aud1 ca1 km1)

      ra_names = PortalUserAdmin.list_users(:ra) |> Enum.map(& &1.username)
      assert Enum.sort(ra_names) == ~w(aud1 ra1 ro1)
    end
  end

  describe "set_status/2" do
    test "suspends and activates" do
      {:ok, user, _} = PortalUserAdmin.create_user(valid_attrs())

      assert {:ok, u1} = PortalUserAdmin.set_status(user.id, "suspended")
      assert u1.status == "suspended"

      assert {:ok, u2} = PortalUserAdmin.set_status(user.id, "active")
      assert u2.status == "active"
    end

    test "rejects invalid status" do
      {:ok, user, _} = PortalUserAdmin.create_user(valid_attrs())
      assert {:error, :invalid_status} = PortalUserAdmin.set_status(user.id, "deleted")
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = PortalUserAdmin.set_status("nope", "active")
    end
  end

  describe "delete_user/1" do
    test "removes the record" do
      {:ok, user, _} = PortalUserAdmin.create_user(valid_attrs())
      assert {:ok, _id} = PortalUserAdmin.delete_user(user.id)
      assert PortalUserAdmin.list_users(:ca) == []
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = PortalUserAdmin.delete_user("nope")
    end
  end

  describe "reset_password/1" do
    test "rotates the hash and returns fresh plaintext" do
      {:ok, user, original_pw} = PortalUserAdmin.create_user(valid_attrs())

      assert {:ok, updated, new_pw} = PortalUserAdmin.reset_password(user.id)
      assert new_pw != original_pw
      assert updated.password_hash != user.password_hash
      assert String.starts_with?(updated.password_hash, "$argon2")
    end

    test "not_found for unknown id" do
      assert {:error, :not_found} = PortalUserAdmin.reset_password("nope")
    end
  end
end
