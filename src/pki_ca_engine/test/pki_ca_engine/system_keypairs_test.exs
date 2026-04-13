defmodule PkiCaEngine.SystemKeypairsTest do
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.SystemKeypairs
  alias PkiCaEngine.KeyVault
  alias PkiCaEngine.KeypairACL
  alias PkiCaEngine.CredentialManager
  alias PkiCaEngine.Schema.CaInstance

  @admin_password "system-kp-test-password-123"

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "syskp-test-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    # Create an admin user with credentials
    {:ok, admin} =
      CredentialManager.create_user_with_credentials(
        nil,
        ca.id,
        %{username: "syskp-admin-#{System.unique_integer([:positive])}", display_name: "Admin", role: "ca_admin"},
        @admin_password
      )

    admin_kem_cred = CredentialManager.get_kem_credential(nil, admin.id)

    # Initialize the ACL
    {:ok, _acl_result} = KeypairACL.initialize(ca.id, admin_kem_cred.public_key)

    {:ok, acl_pub_keys} = KeypairACL.get_public_keys()

    %{ca: ca, acl_kem_public_key: acl_pub_keys.kem_public_key}
  end

  describe "create_all/3" do
    test "creates 4 keypairs in Key Vault", %{ca: ca, acl_kem_public_key: kem_pub} do
      assert {:ok, keypairs} = SystemKeypairs.create_all(ca.id, kem_pub)
      assert length(keypairs) == 4
    end

    test "all keypairs have status pending", %{ca: ca, acl_kem_public_key: kem_pub} do
      assert {:ok, keypairs} = SystemKeypairs.create_all(ca.id, kem_pub)

      Enum.each(keypairs, fn kp ->
        assert kp.status == "pending"
      end)
    end

    test "each keypair has correct name", %{ca: ca, acl_kem_public_key: kem_pub} do
      assert {:ok, keypairs} = SystemKeypairs.create_all(ca.id, kem_pub)

      names = Enum.map(keypairs, & &1.name) |> Enum.sort()
      expected = SystemKeypairs.list_names() |> Enum.sort()
      assert names == expected
    end

    test "keypairs are retrievable from Key Vault", %{ca: ca, acl_kem_public_key: kem_pub} do
      assert {:ok, keypairs} = SystemKeypairs.create_all(ca.id, kem_pub)

      Enum.each(keypairs, fn kp ->
        assert KeyVault.get_keypair(kp.id) != nil
      end)
    end
  end

  describe "list_names/0" do
    test "returns 4 names" do
      names = SystemKeypairs.list_names()
      assert length(names) == 4
    end
  end
end
