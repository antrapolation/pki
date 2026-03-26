defmodule PkiPlatformEngine.TenantTest do
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.Tenant
  alias PkiPlatformEngine.PlatformRepo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(PlatformRepo)
    :ok
  end

  @valid_attrs %{name: "Acme Corp", slug: "acme-corp"}

  describe "changeset/2" do
    test "create tenant with valid attrs succeeds with UUIDv7 id and auto-generated database_name" do
      changeset = Tenant.changeset(%Tenant{}, @valid_attrs)
      assert changeset.valid?

      {:ok, tenant} = PlatformRepo.insert(changeset)
      assert tenant.id != nil
      assert tenant.database_name =~ ~r/^pki_tenant_[a-f0-9]+$/
      assert tenant.status == "initialized"
    end

    test "create tenant with missing name returns validation error" do
      changeset = Tenant.changeset(%Tenant{}, %{slug: "test-slug"})
      refute changeset.valid?
      assert %{name: ["can't be blank"]} = errors_on(changeset)
    end

    test "create tenant with missing slug returns validation error" do
      changeset = Tenant.changeset(%Tenant{}, %{name: "Test"})
      refute changeset.valid?
      assert %{slug: ["can't be blank"]} = errors_on(changeset)
    end

    test "create tenant with invalid slug returns validation error" do
      changeset = Tenant.changeset(%Tenant{}, %{name: "Test", slug: "INVALID SLUG!"})
      refute changeset.valid?
      assert %{slug: ["must be lowercase alphanumeric with hyphens"]} = errors_on(changeset)
    end

    test "create tenant with duplicate slug returns unique constraint error" do
      {:ok, _} = PlatformRepo.insert(Tenant.changeset(%Tenant{}, @valid_attrs))

      {:error, changeset} =
        PlatformRepo.insert(Tenant.changeset(%Tenant{}, %{name: "Other Corp", slug: "acme-corp"}))

      assert %{slug: ["has already been taken"]} = errors_on(changeset)
    end

    test "create tenant with duplicate name returns unique constraint error" do
      {:ok, _} = PlatformRepo.insert(Tenant.changeset(%Tenant{}, @valid_attrs))

      {:error, changeset} =
        PlatformRepo.insert(Tenant.changeset(%Tenant{}, %{name: "Acme Corp", slug: "acme-corp-2"}))

      assert %{name: ["has already been taken"]} = errors_on(changeset)
    end

    test "status must be one of: initialized, active, suspended" do
      changeset = Tenant.changeset(%Tenant{}, Map.put(@valid_attrs, :status, "deleted"))
      refute changeset.valid?
      assert %{status: ["is invalid"]} = errors_on(changeset)

      for status <- ["initialized", "active", "suspended"] do
        changeset = Tenant.changeset(%Tenant{}, Map.put(@valid_attrs, :status, status))
        assert changeset.valid?, "Expected status '#{status}' to be valid"
      end
    end

    test "default signing_algorithm is ECC-P256" do
      {:ok, tenant} = PlatformRepo.insert(Tenant.changeset(%Tenant{}, @valid_attrs))
      assert tenant.signing_algorithm == "ECC-P256"
    end

    test "default kem_algorithm is ECDH-P256" do
      {:ok, tenant} = PlatformRepo.insert(Tenant.changeset(%Tenant{}, @valid_attrs))
      assert tenant.kem_algorithm == "ECDH-P256"
    end

    test "database_name is auto-generated from id" do
      changeset = Tenant.changeset(%Tenant{}, @valid_attrs)
      id = Ecto.Changeset.get_field(changeset, :id)
      db_name = Ecto.Changeset.get_field(changeset, :database_name)
      assert db_name == "pki_tenant_" <> String.replace(id, "-", "")
    end

    test "update tenant status" do
      {:ok, tenant} = PlatformRepo.insert(Tenant.changeset(%Tenant{}, @valid_attrs))
      assert tenant.status == "initialized"

      {:ok, updated} = PlatformRepo.update(Tenant.changeset(tenant, %{status: "active"}))
      assert updated.status == "active"
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
