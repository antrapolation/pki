defmodule PkiPlatformEngine.TenantTest do
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.Tenant
  alias PkiPlatformEngine.PlatformRepo

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(PlatformRepo)
    :ok
  end

  @valid_attrs %{name: "Acme Corp", slug: "acme-corp", email: "admin@acme.test"}

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
      changeset = Tenant.changeset(%Tenant{}, %{slug: "test-slug", email: "t@t.test"})
      refute changeset.valid?
      assert %{name: ["can't be blank"]} = errors_on(changeset)
    end

    test "create tenant with missing slug returns validation error" do
      changeset = Tenant.changeset(%Tenant{}, %{name: "Test", email: "t@t.test"})
      refute changeset.valid?
      assert %{slug: ["can't be blank"]} = errors_on(changeset)
    end

    test "create tenant with invalid slug returns validation error" do
      changeset = Tenant.changeset(%Tenant{}, %{name: "Test", slug: "INVALID SLUG!", email: "t@t.test"})
      refute changeset.valid?
      assert %{slug: ["must be lowercase alphanumeric with hyphens"]} = errors_on(changeset)
    end

    test "create tenant with duplicate slug returns unique constraint error" do
      {:ok, _} = PlatformRepo.insert(Tenant.changeset(%Tenant{}, @valid_attrs))

      {:error, changeset} =
        PlatformRepo.insert(Tenant.changeset(%Tenant{}, %{name: "Other Corp", slug: "acme-corp", email: "other@acme.test"}))

      assert %{slug: ["has already been taken"]} = errors_on(changeset)
    end

    test "create tenant with duplicate name returns unique constraint error" do
      {:ok, _} = PlatformRepo.insert(Tenant.changeset(%Tenant{}, @valid_attrs))

      {:error, changeset} =
        PlatformRepo.insert(Tenant.changeset(%Tenant{}, %{name: "Acme Corp", slug: "acme-corp-2", email: "dup@acme.test"}))

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

    test "default max_ca_depth is 2" do
      changeset = Tenant.changeset(%Tenant{}, @valid_attrs)
      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :max_ca_depth) == 2
    end

    test "custom max_ca_depth value is accepted" do
      changeset = Tenant.changeset(%Tenant{}, Map.put(@valid_attrs, :max_ca_depth, 5))
      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :max_ca_depth) == 5
    end

    test "max_ca_depth must be greater than 0" do
      changeset = Tenant.changeset(%Tenant{}, Map.put(@valid_attrs, :max_ca_depth, 0))
      refute changeset.valid?
      assert %{max_ca_depth: [_]} = errors_on(changeset)
    end

    test "max_ca_depth above 10 is allowed" do
      changeset = Tenant.changeset(%Tenant{}, Map.put(@valid_attrs, :max_ca_depth, 11))
      assert changeset.valid?
    end

    test "valid without signing_algorithm field" do
      changeset = Tenant.changeset(%Tenant{}, @valid_attrs)
      assert changeset.valid?
      refute Map.has_key?(changeset.data |> Map.from_struct(), :signing_algorithm)
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
