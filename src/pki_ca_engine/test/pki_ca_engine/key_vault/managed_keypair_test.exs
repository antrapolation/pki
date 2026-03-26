defmodule PkiCaEngine.KeyVault.ManagedKeypairTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeyVault.ManagedKeypair
  alias PkiCaEngine.Schema.CaInstance

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "vault-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    valid_attrs = %{
      name: "root-signing-key",
      algorithm: "ECC-P256",
      protection_mode: "credential_own",
      public_key: <<1, 2, 3, 4>>,
      ca_instance_id: ca.id
    }

    %{ca: ca, valid_attrs: valid_attrs}
  end

  describe "changeset/2" do
    test "valid attrs produce a valid changeset with UUIDv7 id", %{valid_attrs: attrs} do
      changeset = ManagedKeypair.changeset(%ManagedKeypair{}, attrs)
      assert changeset.valid?
      id = Ecto.Changeset.get_field(changeset, :id)
      assert is_binary(id)
      assert byte_size(id) == 36
    end

    test "protection_mode must be credential_own, split_auth_token, or split_key", %{valid_attrs: attrs} do
      changeset = ManagedKeypair.changeset(%ManagedKeypair{}, %{attrs | protection_mode: "plaintext"})
      refute changeset.valid?
      assert %{protection_mode: [_]} = errors_on(changeset)

      for valid_mode <- ["credential_own", "split_auth_token", "split_key"] do
        changeset = ManagedKeypair.changeset(%ManagedKeypair{}, %{attrs | protection_mode: valid_mode})
        assert changeset.valid?
      end
    end

    test "status must be pending, active, suspended, or archived", %{valid_attrs: attrs} do
      changeset = ManagedKeypair.changeset(%ManagedKeypair{}, Map.put(attrs, :status, "deleted"))
      refute changeset.valid?
      assert %{status: [_]} = errors_on(changeset)

      for valid_status <- ["pending", "active", "suspended", "archived"] do
        changeset = ManagedKeypair.changeset(%ManagedKeypair{}, Map.put(attrs, :status, valid_status))
        assert changeset.valid?
      end
    end

    test "default status is pending", %{valid_attrs: attrs} do
      changeset = ManagedKeypair.changeset(%ManagedKeypair{}, attrs)
      assert Ecto.Changeset.get_field(changeset, :status) == "pending"
    end

    test "required fields are enforced" do
      changeset = ManagedKeypair.changeset(%ManagedKeypair{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{name: ["can't be blank"]} = errors
      assert %{algorithm: ["can't be blank"]} = errors
      assert %{protection_mode: ["can't be blank"]} = errors
      assert %{public_key: ["can't be blank"]} = errors
      assert %{ca_instance_id: ["can't be blank"]} = errors
    end
  end

  describe "database operations" do
    test "insert and retrieve managed keypair", %{valid_attrs: attrs} do
      {:ok, keypair} = Repo.insert(ManagedKeypair.changeset(%ManagedKeypair{}, attrs))
      assert keypair.name == "root-signing-key"
      assert keypair.algorithm == "ECC-P256"
      assert keypair.protection_mode == "credential_own"
      assert keypair.status == "pending"
      assert keypair.metadata == %{}
    end

    test "name + ca_instance_id unique constraint", %{valid_attrs: attrs} do
      {:ok, _} = Repo.insert(ManagedKeypair.changeset(%ManagedKeypair{}, attrs))

      {:error, changeset} =
        Repo.insert(ManagedKeypair.changeset(%ManagedKeypair{}, attrs))

      assert %{ca_instance_id: ["has already been taken"]} = errors_on(changeset)
    end

    test "grants association loads empty list", %{valid_attrs: attrs} do
      {:ok, keypair} = Repo.insert(ManagedKeypair.changeset(%ManagedKeypair{}, attrs))
      keypair = Repo.preload(keypair, :grants)
      assert keypair.grants == []
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
