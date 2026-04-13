defmodule PkiCaEngine.BootstrapTest do
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.Bootstrap
  alias PkiCaEngine.KeypairACL
  alias PkiCaEngine.KeyVault
  alias PkiCaEngine.Schema.{CaInstance, CaUser}

  @password "bootstrap-test-password-123"

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "bootstrap-test-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    admin_attrs = %{
      username: "bootstrap-admin-#{System.unique_integer([:positive])}",
      display_name: "Bootstrap Admin",
      role: "ca_admin"
    }

    %{ca: ca, admin_attrs: admin_attrs}
  end

  describe "setup_tenant/4" do
    test "creates admin user with credentials", %{ca: ca, admin_attrs: attrs} do
      assert {:ok, result} = Bootstrap.setup_tenant(nil, ca.id, attrs, @password)
      assert %CaUser{} = result.admin
      assert result.admin.username == attrs.username
      assert result.admin.role == "ca_admin"
    end

    test "admin has signing + KEM credentials", %{ca: ca, admin_attrs: attrs} do
      assert {:ok, result} = Bootstrap.setup_tenant(nil, ca.id, attrs, @password)

      types = Enum.map(result.admin.credentials, & &1.credential_type) |> Enum.sort()
      assert types == ["kem", "signing"]
    end

    test "ACL is initialized after setup", %{ca: ca, admin_attrs: attrs} do
      assert {:ok, _result} = Bootstrap.setup_tenant(nil, ca.id, attrs, @password)
      assert KeypairACL.initialized?(ca.id)
    end

    test "4 system keypairs created", %{ca: ca, admin_attrs: attrs} do
      assert {:ok, result} = Bootstrap.setup_tenant(nil, ca.id, attrs, @password)
      assert length(result.system_keypairs) == 4
    end

    test "full result contains admin, acl, and system_keypairs", %{ca: ca, admin_attrs: attrs} do
      assert {:ok, result} = Bootstrap.setup_tenant(nil, ca.id, attrs, @password)

      assert Map.has_key?(result, :admin)
      assert Map.has_key?(result, :acl)
      assert Map.has_key?(result, :system_keypairs)

      # ACL result has expected keys
      assert Map.has_key?(result.acl, :acl_signing)
      assert Map.has_key?(result.acl, :acl_kem)
      assert Map.has_key?(result.acl, :encrypted_acl_password)
    end

    test "setup_tenant with invalid admin attrs rolls back, nothing created", %{ca: ca} do
      invalid_attrs = %{username: nil, display_name: nil, role: "ca_admin"}

      assert {:error, {:admin_creation_failed, _reason}} =
               Bootstrap.setup_tenant(nil, ca.id, invalid_attrs, @password)

      # Nothing should exist
      refute KeypairACL.initialized?(ca.id)
      assert KeyVault.list_keypairs(ca.id) == []
    end

    test "after setup, KeypairACL.initialized? returns true", %{ca: ca, admin_attrs: attrs} do
      refute KeypairACL.initialized?(ca.id)
      assert {:ok, _result} = Bootstrap.setup_tenant(nil, ca.id, attrs, @password)
      assert KeypairACL.initialized?(ca.id)
    end
  end
end
