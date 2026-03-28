defmodule PkiCaEngine.CredentialManager.CredentialTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.CredentialManager.Credential
  alias PkiCaEngine.Schema.{CaInstance, CaUser}

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{name: "cred-ca-#{System.unique_integer([:positive])}", created_by: "admin"})
      )

    {:ok, user} =
      Repo.insert(
        CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "ca_admin", display_name: "Test Admin"})
      )

    valid_attrs = %{
      credential_type: "signing",
      algorithm: "ECC-P256",
      public_key: <<1, 2, 3, 4>>,
      encrypted_private_key: <<5, 6, 7, 8>>,
      salt: <<9, 10, 11, 12>>,
      user_id: user.id
    }

    %{ca: ca, user: user, valid_attrs: valid_attrs}
  end

  describe "changeset/2" do
    test "valid attrs produce a valid changeset with UUIDv7 id", %{valid_attrs: attrs} do
      changeset = Credential.changeset(%Credential{}, attrs)
      assert changeset.valid?
      id = Ecto.Changeset.get_field(changeset, :id)
      assert is_binary(id)
      assert byte_size(id) == 36
    end

    test "credential_type must be signing or kem", %{valid_attrs: attrs} do
      changeset = Credential.changeset(%Credential{}, %{attrs | credential_type: "encryption"})
      refute changeset.valid?
      assert %{credential_type: [_]} = errors_on(changeset)

      for valid_type <- ["signing", "kem"] do
        changeset = Credential.changeset(%Credential{}, %{attrs | credential_type: valid_type})
        assert changeset.valid?
      end
    end

    test "status must be active or revoked", %{valid_attrs: attrs} do
      changeset = Credential.changeset(%Credential{}, Map.put(attrs, :status, "expired"))
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)

      for valid_status <- ["active", "revoked"] do
        changeset = Credential.changeset(%Credential{}, Map.put(attrs, :status, valid_status))
        assert changeset.valid?
      end
    end

    test "required fields are enforced" do
      changeset = Credential.changeset(%Credential{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{credential_type: ["can't be blank"]} = errors
      assert %{algorithm: ["can't be blank"]} = errors
      assert %{public_key: ["can't be blank"]} = errors
      assert %{encrypted_private_key: ["can't be blank"]} = errors
      assert %{salt: ["can't be blank"]} = errors
      assert %{user_id: ["can't be blank"]} = errors
    end

    test "default status is active", %{valid_attrs: attrs} do
      changeset = Credential.changeset(%Credential{}, attrs)
      assert Ecto.Changeset.get_field(changeset, :status) == "active"
    end
  end

  describe "database operations" do
    test "user association works - insert and preload", %{valid_attrs: attrs, user: user} do
      {:ok, credential} = Repo.insert(Credential.changeset(%Credential{}, attrs))
      assert credential.user_id == user.id

      credential = Repo.preload(credential, :user)
      assert credential.user.id == user.id
      assert credential.user.display_name == "Test Admin"
    end

    test "create credential with valid attrs succeeds with UUIDv7 id", %{valid_attrs: attrs} do
      {:ok, credential} = Repo.insert(Credential.changeset(%Credential{}, attrs))
      assert is_binary(credential.id)
      assert credential.credential_type == "signing"
      assert credential.algorithm == "ECC-P256"
      assert credential.status == "active"
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
