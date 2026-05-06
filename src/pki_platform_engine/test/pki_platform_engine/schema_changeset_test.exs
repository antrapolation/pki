defmodule PkiPlatformEngine.SchemaChangesetTest do
  @moduledoc """
  Tests for Ecto schema changesets and pure helper functions.
  No database connection required.
  """
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.{PlatformAdmin, UserProfile, UserTenantRole}

  # ---------------------------------------------------------------------------
  # PlatformAdmin changesets
  # ---------------------------------------------------------------------------

  describe "PlatformAdmin.changeset/2" do
    test "valid attrs produce valid changeset" do
      cs = PlatformAdmin.changeset(%PlatformAdmin{}, %{username: "alice", display_name: "Alice"})
      assert cs.valid?
    end

    test "missing username produces error" do
      cs = PlatformAdmin.changeset(%PlatformAdmin{}, %{display_name: "Alice"})
      refute cs.valid?
      assert {:username, _} = List.first(cs.errors)
    end

    test "invalid email format produces error" do
      cs = PlatformAdmin.changeset(%PlatformAdmin{}, %{username: "bob", display_name: "Bob", email: "not-an-email"})
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :email)
    end

    test "valid email passes validation" do
      cs = PlatformAdmin.changeset(%PlatformAdmin{}, %{username: "bob", display_name: "Bob", email: "bob@example.com"})
      assert cs.valid?
    end

    test "invalid status produces error" do
      cs = PlatformAdmin.changeset(%PlatformAdmin{}, %{username: "bob", display_name: "Bob", status: "banned"})
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :status)
    end
  end

  describe "PlatformAdmin.registration_changeset/2" do
    test "valid attrs produce valid changeset" do
      cs = PlatformAdmin.registration_changeset(%PlatformAdmin{}, %{
        username: "admin1",
        display_name: "Admin One",
        password: "securepass123",
        email: "admin@example.com"
      })
      assert cs.valid?
    end

    test "short password produces error" do
      cs = PlatformAdmin.registration_changeset(%PlatformAdmin{}, %{
        username: "admin1",
        display_name: "Admin",
        password: "short"
      })
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :password)
    end

    test "password is hashed after registration_changeset" do
      cs = PlatformAdmin.registration_changeset(%PlatformAdmin{}, %{
        username: "admin1",
        display_name: "Admin",
        password: "securepass123"
      })
      hash = Ecto.Changeset.get_change(cs, :password_hash)
      assert is_binary(hash)
      assert String.starts_with?(hash, "$argon2") or String.starts_with?(hash, "$2b")
    end
  end

  describe "PlatformAdmin.profile_changeset/2" do
    test "accepts display_name and email" do
      cs = PlatformAdmin.profile_changeset(%PlatformAdmin{}, %{display_name: "New Name", email: "new@example.com"})
      assert cs.valid?
    end

    test "rejects invalid email" do
      cs = PlatformAdmin.profile_changeset(%PlatformAdmin{}, %{email: "bad-email"})
      refute cs.valid?
    end
  end

  describe "PlatformAdmin.password_changeset/2" do
    test "accepts valid new password" do
      cs = PlatformAdmin.password_changeset(%PlatformAdmin{}, %{password: "newSecurePass123"})
      assert cs.valid?
    end

    test "rejects short password" do
      cs = PlatformAdmin.password_changeset(%PlatformAdmin{}, %{password: "abc"})
      refute cs.valid?
    end
  end

  # ---------------------------------------------------------------------------
  # UserProfile changesets
  # ---------------------------------------------------------------------------

  describe "UserProfile.changeset/2" do
    test "valid attrs produce valid changeset" do
      cs = UserProfile.changeset(%UserProfile{}, %{username: "alice"})
      assert cs.valid?
    end

    test "short username fails validation" do
      cs = UserProfile.changeset(%UserProfile{}, %{username: "ab"})
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :username)
    end

    test "missing username produces error" do
      cs = UserProfile.changeset(%UserProfile{}, %{display_name: "Alice"})
      refute cs.valid?
    end
  end

  describe "UserProfile.registration_changeset/2" do
    test "valid attrs produce valid changeset" do
      cs = UserProfile.registration_changeset(%UserProfile{}, %{
        username: "alice",
        password: "SecurePass123"
      })
      assert cs.valid?
    end

    test "missing password fails" do
      cs = UserProfile.registration_changeset(%UserProfile{}, %{username: "alice"})
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :password)
    end

    test "password without uppercase fails" do
      cs = UserProfile.registration_changeset(%UserProfile{}, %{username: "alice", password: "securepass123"})
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :password)
    end
  end

  # ---------------------------------------------------------------------------
  # UserTenantRole changesets
  # ---------------------------------------------------------------------------

  describe "UserTenantRole.changeset/2" do
    test "valid attrs produce valid changeset" do
      cs = UserTenantRole.changeset(%UserTenantRole{}, %{
        user_profile_id: "uid-1",
        tenant_id: "tid-1",
        role: "ca_admin",
        portal: "ca"
      })
      assert cs.valid?
    end

    test "invalid role produces error" do
      cs = UserTenantRole.changeset(%UserTenantRole{}, %{
        user_profile_id: "uid-1",
        tenant_id: "tid-1",
        role: "superuser",
        portal: "ca"
      })
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :role)
    end

    test "invalid portal produces error" do
      cs = UserTenantRole.changeset(%UserTenantRole{}, %{
        user_profile_id: "uid-1",
        tenant_id: "tid-1",
        role: "ca_admin",
        portal: "admin"
      })
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :portal)
    end

    test "all valid roles are accepted" do
      for role <- ["ca_admin", "key_manager", "ra_admin", "ra_officer", "auditor", "tenant_admin"] do
        cs = UserTenantRole.changeset(%UserTenantRole{}, %{
          user_profile_id: "u",
          tenant_id: "t",
          role: role,
          portal: "ca"
        })
        assert cs.valid?, "expected #{role} to be valid"
      end
    end

    test "all valid portals are accepted" do
      for portal <- ["ca", "ra", "platform"] do
        cs = UserTenantRole.changeset(%UserTenantRole{}, %{
          user_profile_id: "u",
          tenant_id: "t",
          role: "ca_admin",
          portal: portal
        })
        assert cs.valid?, "expected portal #{portal} to be valid"
      end
    end
  end
end
