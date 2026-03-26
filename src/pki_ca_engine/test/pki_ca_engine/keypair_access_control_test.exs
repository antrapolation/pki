defmodule PkiCaEngine.KeypairAccessControlTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeypairAccessControl
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore, IssuerKey, KeypairAccess}

  setup do
    {:ok, ca} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "kac-test-ca", created_by: "admin"}))

    {:ok, user} =
      Repo.insert(CaUser.changeset(%CaUser{}, %{
        ca_instance_id: ca.id,
        display_name: "User One",
        role: "key_manager"
      }))

    {:ok, granter} =
      Repo.insert(CaUser.changeset(%CaUser{}, %{
        ca_instance_id: ca.id,
        display_name: "Granter",
        role: "ca_admin"
      }))

    {:ok, keystore} =
      Repo.insert(Keystore.changeset(%Keystore{}, %{
        ca_instance_id: ca.id,
        type: "software"
      }))

    {:ok, issuer_key} =
      Repo.insert(IssuerKey.changeset(%IssuerKey{}, %{
        ca_instance_id: ca.id,
        key_alias: "root-key-1",
        algorithm: "RSA-2048"
      }))

    %{ca: ca, user: user, granter: granter, keystore: keystore, issuer_key: issuer_key}
  end

  # -- grant_access/3 --

  describe "grant_access/3" do
    test "grants a user access to a key", %{issuer_key: key, user: user, granter: granter} do
      assert {:ok, %KeypairAccess{} = access} =
               KeypairAccessControl.grant_access(key.id, user.id, granter.id)

      assert access.issuer_key_id == key.id
      assert access.user_id == user.id
      assert access.granted_by == granter.id
      assert access.granted_at != nil
    end

    test "duplicate grant returns error", %{issuer_key: key, user: user, granter: granter} do
      assert {:ok, _} = KeypairAccessControl.grant_access(key.id, user.id, granter.id)
      assert {:error, changeset} = KeypairAccessControl.grant_access(key.id, user.id, granter.id)
      assert %{issuer_key_id: [_]} = errors_on(changeset)
    end
  end

  # -- revoke_access/2 --

  describe "revoke_access/2" do
    test "revokes user's access to a key", %{issuer_key: key, user: user, granter: granter} do
      {:ok, _} = KeypairAccessControl.grant_access(key.id, user.id, granter.id)
      assert {:ok, count} = KeypairAccessControl.revoke_access(key.id, user.id)
      assert count == 1
    end

    test "returns zero count when no access exists", %{issuer_key: key, user: user} do
      assert {:ok, 0} = KeypairAccessControl.revoke_access(key.id, user.id)
    end
  end

  # -- has_access?/2 --

  describe "has_access?/2" do
    test "returns true when user has access", %{issuer_key: key, user: user, granter: granter} do
      {:ok, _} = KeypairAccessControl.grant_access(key.id, user.id, granter.id)
      assert KeypairAccessControl.has_access?(key.id, user.id) == true
    end

    test "returns false when user does not have access", %{issuer_key: key, user: user} do
      assert KeypairAccessControl.has_access?(key.id, user.id) == false
    end
  end

  # -- list_access/1 --

  describe "list_access/1" do
    test "lists all users with access to a key", %{issuer_key: key, user: user, granter: granter, ca: ca} do
      {:ok, user2} =
        Repo.insert(CaUser.changeset(%CaUser{}, %{
          ca_instance_id: ca.id,
          role: "key_manager"
        }))

      {:ok, _} = KeypairAccessControl.grant_access(key.id, user.id, granter.id)
      {:ok, _} = KeypairAccessControl.grant_access(key.id, user2.id, granter.id)

      accesses = KeypairAccessControl.list_access(key.id)
      assert length(accesses) == 2
    end

    test "returns empty list when no access granted", %{issuer_key: key} do
      assert KeypairAccessControl.list_access(key.id) == []
    end
  end

  # -- list_keys_for_user/1 --

  describe "list_keys_for_user/1" do
    test "lists all keys a user can access", %{issuer_key: key, user: user, granter: granter, ca: ca} do
      {:ok, key2} =
        Repo.insert(IssuerKey.changeset(%IssuerKey{}, %{
          ca_instance_id: ca.id,
          key_alias: "sub-key-1",
          algorithm: "ECDSA-P256"
        }))

      {:ok, _} = KeypairAccessControl.grant_access(key.id, user.id, granter.id)
      {:ok, _} = KeypairAccessControl.grant_access(key2.id, user.id, granter.id)

      accesses = KeypairAccessControl.list_keys_for_user(user.id)
      assert length(accesses) == 2
    end

    test "returns empty list when user has no access", %{user: user} do
      assert KeypairAccessControl.list_keys_for_user(user.id) == []
    end
  end

  # -- Helper --

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
