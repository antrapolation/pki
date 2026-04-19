defmodule PkiTenant.PortalUserManagementTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.PortalUser
  alias PkiMnesia.TestHelper
  alias PkiTenant.PortalUserManagement

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  defp insert_user(attrs \\ %{}) do
    defaults = %{
      username: "alice-#{System.unique_integer([:positive])}",
      password_hash: Argon2.hash_pwd_salt("originalpassw0rd!"),
      display_name: "Alice Example",
      email: "alice@example.com",
      role: :ca_admin,
      status: "active"
    }

    user = PortalUser.new(Map.merge(defaults, attrs))
    {:ok, stored} = Repo.insert(user)
    stored
  end

  describe "update_profile/2" do
    test "updates display_name and email" do
      user = insert_user()

      assert {:ok, updated} =
               PortalUserManagement.update_profile(user.id, %{
                 display_name: "Alice Prime",
                 email: "alice.prime@example.com"
               })

      assert updated.display_name == "Alice Prime"
      assert updated.email == "alice.prime@example.com"
    end

    test "trims whitespace and lowercases email" do
      user = insert_user()

      assert {:ok, updated} =
               PortalUserManagement.update_profile(user.id, %{
                 display_name: "  Alice  ",
                 email: "  ALICE@Example.COM  "
               })

      assert updated.display_name == "Alice"
      assert updated.email == "alice@example.com"
    end

    test "rejects invalid email shape" do
      user = insert_user()

      assert {:error, :invalid_email} =
               PortalUserManagement.update_profile(user.id, %{email: "not-an-email"})
    end

    test "rejects a display_name that's too long" do
      user = insert_user()
      long_name = String.duplicate("x", 200)

      assert {:error, :invalid_display_name} =
               PortalUserManagement.update_profile(user.id, %{display_name: long_name})
    end

    test "returns :not_found when user doesn't exist" do
      assert {:error, :not_found} =
               PortalUserManagement.update_profile("nonexistent", %{display_name: "Test"})
    end

    test "accepts string-keyed attrs (LiveView form shape)" do
      user = insert_user()

      assert {:ok, updated} =
               PortalUserManagement.update_profile(user.id, %{
                 "display_name" => "String Keys",
                 "email" => "string@example.com"
               })

      assert updated.display_name == "String Keys"
    end
  end

  describe "verify_and_change_password/4" do
    test "changes the password when current is correct" do
      user = insert_user()

      assert {:ok, updated} =
               PortalUserManagement.verify_and_change_password(
                 user.id,
                 "originalpassw0rd!",
                 "newpassword!@#$",
                 "newpassword!@#$"
               )

      assert updated.password_hash != user.password_hash
      assert String.starts_with?(updated.password_hash, "$argon2")
      assert Argon2.verify_pass("newpassword!@#$", updated.password_hash)
    end

    test "rejects when current password is wrong" do
      user = insert_user()

      assert {:error, :wrong_password} =
               PortalUserManagement.verify_and_change_password(
                 user.id,
                 "wrong-current",
                 "newpassword!@#$",
                 "newpassword!@#$"
               )
    end

    test "rejects when new != confirmation" do
      user = insert_user()

      assert {:error, :password_mismatch} =
               PortalUserManagement.verify_and_change_password(
                 user.id,
                 "originalpassw0rd!",
                 "newpassword!@#$",
                 "different-confirm"
               )
    end

    test "rejects when new password is too short" do
      user = insert_user()

      assert {:error, :weak_password} =
               PortalUserManagement.verify_and_change_password(
                 user.id,
                 "originalpassw0rd!",
                 "short",
                 "short"
               )
    end

    test "checks mismatch before weakness (so users don't see double errors)" do
      user = insert_user()

      assert {:error, :password_mismatch} =
               PortalUserManagement.verify_and_change_password(
                 user.id,
                 "originalpassw0rd!",
                 "short",
                 "different-short"
               )
    end

    test "verifies bcrypt-hashed legacy passwords too" do
      # Simulate a legacy record with a Bcrypt hash
      legacy_hash = Bcrypt.hash_pwd_salt("legacy-password-xyz")
      user = insert_user(%{password_hash: legacy_hash})

      assert {:ok, updated} =
               PortalUserManagement.verify_and_change_password(
                 user.id,
                 "legacy-password-xyz",
                 "newpassword!@#$",
                 "newpassword!@#$"
               )

      # New hash is Argon2 — legacy records auto-upgrade on password change
      assert String.starts_with?(updated.password_hash, "$argon2")
    end

    test "returns :not_found when user doesn't exist" do
      assert {:error, :not_found} =
               PortalUserManagement.verify_and_change_password(
                 "nonexistent",
                 "any",
                 "newpassword!@#$",
                 "newpassword!@#$"
               )
    end
  end
end
