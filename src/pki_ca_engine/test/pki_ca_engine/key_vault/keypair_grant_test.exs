defmodule PkiCaEngine.KeyVault.KeypairGrantTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeyVault.{ManagedKeypair, KeypairGrant}
  alias PkiCaEngine.CredentialManager.Credential
  alias PkiCaEngine.Schema.{CaInstance, CaUser}

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "grant-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    {:ok, user} =
      Repo.insert(
        CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "key_manager", display_name: "Key Mgr"})
      )

    {:ok, credential} =
      Repo.insert(
        Credential.changeset(%Credential{}, %{
          credential_type: "kem",
          algorithm: "ECC-P256",
          public_key: <<1, 2, 3, 4>>,
          encrypted_private_key: <<5, 6, 7, 8>>,
          salt: <<9, 10, 11, 12>>,
          user_id: user.id
        })
      )

    {:ok, keypair} =
      Repo.insert(
        ManagedKeypair.changeset(%ManagedKeypair{}, %{
          name: "grant-test-key",
          algorithm: "ECC-P256",
          protection_mode: "credential_own",
          public_key: <<1, 2, 3, 4>>,
          ca_instance_id: ca.id
        })
      )

    valid_attrs = %{
      signed_envelope: <<10, 20, 30, 40>>,
      granted_at: DateTime.utc_now(),
      managed_keypair_id: keypair.id,
      credential_id: credential.id
    }

    %{ca: ca, user: user, credential: credential, keypair: keypair, valid_attrs: valid_attrs}
  end

  describe "changeset/2" do
    test "valid attrs produce a valid changeset with UUIDv7 id", %{valid_attrs: attrs} do
      changeset = KeypairGrant.changeset(%KeypairGrant{}, attrs)
      assert changeset.valid?
      id = Ecto.Changeset.get_field(changeset, :id)
      assert is_binary(id)
      assert byte_size(id) == 36
    end

    test "required fields are enforced" do
      changeset = KeypairGrant.changeset(%KeypairGrant{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{signed_envelope: ["can't be blank"]} = errors
      assert %{granted_at: ["can't be blank"]} = errors
      assert %{managed_keypair_id: ["can't be blank"]} = errors
      assert %{credential_id: ["can't be blank"]} = errors
    end
  end

  describe "database operations" do
    test "insert grant with valid attrs", %{valid_attrs: attrs} do
      {:ok, grant} = Repo.insert(KeypairGrant.changeset(%KeypairGrant{}, attrs))
      assert grant.signed_envelope == <<10, 20, 30, 40>>
      assert grant.managed_keypair_id == attrs.managed_keypair_id
      assert grant.credential_id == attrs.credential_id
      assert is_nil(grant.revoked_at)
    end

    test "unique constraint on (managed_keypair_id, credential_id)", %{valid_attrs: attrs} do
      {:ok, _} = Repo.insert(KeypairGrant.changeset(%KeypairGrant{}, attrs))

      {:error, changeset} =
        Repo.insert(KeypairGrant.changeset(%KeypairGrant{}, attrs))

      assert %{managed_keypair_id: ["has already been taken"]} = errors_on(changeset)
    end

    test "preload associations", %{valid_attrs: attrs, keypair: keypair, credential: credential} do
      {:ok, grant} = Repo.insert(KeypairGrant.changeset(%KeypairGrant{}, attrs))
      grant = Repo.preload(grant, [:managed_keypair, :credential])
      assert grant.managed_keypair.id == keypair.id
      assert grant.credential.id == credential.id
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
