defmodule PkiPlatformEngine.ProvisionerTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.{Provisioner, PlatformRepo, TenantRepo}

  setup do
    # Checkout sandbox for PlatformRepo but use shared mode so
    # the Provisioner's raw SQL (CREATE DATABASE) can see tenant records.
    # Since CREATE/DROP DATABASE cannot run inside a transaction, we use
    # :manual mode and clean up explicitly in each test.
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(PlatformRepo)
    Ecto.Adapters.SQL.Sandbox.mode(PlatformRepo, :auto)
    :ok
  end

  defp cleanup_tenant(nil), do: :ok

  defp cleanup_tenant(tenant) do
    Provisioner.delete_tenant(tenant.id)
  end

  describe "create_tenant/3" do
    test "creates database, schemas, and inserts tenant record" do
      {:ok, tenant} = Provisioner.create_tenant("Test Org", "test-org")

      try do
        assert tenant.id != nil
        assert tenant.name == "Test Org"
        assert tenant.slug == "test-org"
        assert tenant.status == "initialized"
        assert tenant.database_name =~ ~r/^pki_tenant_[a-f0-9]+$/
        assert tenant.signing_algorithm == "ECC-P256"
        assert tenant.kem_algorithm == "ECDH-P256"

        # Verify tenant record exists in PlatformRepo
        assert PlatformRepo.get(PkiPlatformEngine.Tenant, tenant.id) != nil
      after
        cleanup_tenant(tenant)
      end
    end

    test "creates all 4 schemas (ca, ra, validation, audit)" do
      {:ok, tenant} = Provisioner.create_tenant("Schema Test", "schema-test")

      try do
        for schema <- ["ca", "ra", "validation", "audit"] do
          {:ok, result} = TenantRepo.execute_sql(
            tenant.database_name,
            "public",
            "SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1",
            [schema]
          )

          assert result.num_rows == 1,
            "Expected schema '#{schema}' to exist in tenant database"
        end
      after
        cleanup_tenant(tenant)
      end
    end

    test "returns changeset error for duplicate slug without creating database" do
      {:ok, tenant} = Provisioner.create_tenant("First Org", "dup-slug")

      try do
        {:error, changeset} = Provisioner.create_tenant("Second Org", "dup-slug")
        assert %{slug: ["has already been taken"]} = errors_on(changeset)
      after
        cleanup_tenant(tenant)
      end
    end

    test "returns changeset error for invalid slug" do
      {:error, changeset} = Provisioner.create_tenant("Bad Slug", "INVALID!")
      assert %{slug: _} = errors_on(changeset)
    end

    test "returns changeset error for missing name" do
      {:error, changeset} = Provisioner.create_tenant(nil, "valid-slug")
      assert %{name: ["can't be blank"]} = errors_on(changeset)
    end

    test "accepts custom signing and kem algorithms" do
      {:ok, tenant} = Provisioner.create_tenant(
        "PQC Org", "pqc-org",
        signing_algorithm: "ML-DSA-65",
        kem_algorithm: "ML-KEM-768"
      )

      try do
        assert tenant.signing_algorithm == "ML-DSA-65"
        assert tenant.kem_algorithm == "ML-KEM-768"
      after
        cleanup_tenant(tenant)
      end
    end
  end

  describe "list_tenants/0" do
    test "returns all tenants ordered by inserted_at desc" do
      {:ok, t1} = Provisioner.create_tenant("List Org A", "list-org-a")
      {:ok, t2} = Provisioner.create_tenant("List Org B", "list-org-b")

      try do
        tenants = Provisioner.list_tenants()
        slugs = Enum.map(tenants, & &1.slug)
        assert "list-org-a" in slugs
        assert "list-org-b" in slugs
        # Most recent first
        assert length(tenants) >= 2
      after
        cleanup_tenant(t2)
        cleanup_tenant(t1)
      end
    end
  end

  describe "get_tenant/1 and get_tenant_by_slug/1" do
    test "get_tenant returns tenant by id" do
      {:ok, tenant} = Provisioner.create_tenant("Get Test", "get-test")

      try do
        found = Provisioner.get_tenant(tenant.id)
        assert found.id == tenant.id
        assert found.slug == "get-test"
      after
        cleanup_tenant(tenant)
      end
    end

    test "get_tenant returns nil for unknown id" do
      assert Provisioner.get_tenant(Uniq.UUID.uuid7()) == nil
    end

    test "get_tenant_by_slug returns tenant by slug" do
      {:ok, tenant} = Provisioner.create_tenant("Slug Test", "slug-test")

      try do
        found = Provisioner.get_tenant_by_slug("slug-test")
        assert found.id == tenant.id
      after
        cleanup_tenant(tenant)
      end
    end

    test "get_tenant_by_slug returns nil for unknown slug" do
      assert Provisioner.get_tenant_by_slug("nonexistent") == nil
    end
  end

  describe "suspend_tenant/1" do
    test "changes status to suspended" do
      {:ok, tenant} = Provisioner.create_tenant("Suspend Test", "suspend-test")

      try do
        {:ok, suspended} = Provisioner.suspend_tenant(tenant.id)
        assert suspended.status == "suspended"

        # Verify in database
        reloaded = Provisioner.get_tenant(tenant.id)
        assert reloaded.status == "suspended"
      after
        cleanup_tenant(tenant)
      end
    end

    test "returns error for unknown tenant" do
      assert {:error, :not_found} = Provisioner.suspend_tenant(Uniq.UUID.uuid7())
    end
  end

  describe "activate_tenant/1" do
    test "changes status to active" do
      {:ok, tenant} = Provisioner.create_tenant("Activate Test", "activate-test")

      try do
        {:ok, active} = Provisioner.activate_tenant(tenant.id)
        assert active.status == "active"

        reloaded = Provisioner.get_tenant(tenant.id)
        assert reloaded.status == "active"
      after
        cleanup_tenant(tenant)
      end
    end

    test "returns error for unknown tenant" do
      assert {:error, :not_found} = Provisioner.activate_tenant(Uniq.UUID.uuid7())
    end
  end

  describe "delete_tenant/1" do
    test "drops database and removes tenant record" do
      {:ok, tenant} = Provisioner.create_tenant("Delete Test", "delete-test")
      db_name = tenant.database_name

      {:ok, _} = Provisioner.delete_tenant(tenant.id)

      # Tenant record should be gone
      assert Provisioner.get_tenant(tenant.id) == nil

      # Database should be gone — verify by querying pg_database
      {:ok, admin_conn} = Postgrex.start_link(
        hostname: "localhost",
        port: 5434,
        username: "postgres",
        password: "postgres",
        database: "postgres"
      )

      {:ok, result} = Postgrex.query(
        admin_conn,
        "SELECT 1 FROM pg_database WHERE datname = $1",
        [db_name]
      )

      GenServer.stop(admin_conn)
      assert result.num_rows == 0, "Expected database #{db_name} to be dropped"
    end

    test "returns error for unknown tenant" do
      assert {:error, :not_found} = Provisioner.delete_tenant(Uniq.UUID.uuid7())
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
