defmodule PkiPlatformEngine.ProvisionerTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.{Provisioner, PlatformRepo, TenantPrefix, TenantRepo}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(PlatformRepo)
    Ecto.Adapters.SQL.Sandbox.mode(PlatformRepo, :auto)
    :ok
  end

  defp cleanup_tenant(nil), do: :ok

  defp cleanup_tenant(tenant) do
    Provisioner.delete_tenant(tenant.id)
  end

  # ── Schema-mode provisioning (default) ────────────────────────────────

  describe "create_tenant/3 (schema mode)" do
    test "creates schemas in shared DB and inserts tenant record" do
      {:ok, tenant} = Provisioner.create_tenant("Schema Org", "schema-org", email: "test@example.com")

      try do
        assert tenant.id != nil
        assert tenant.name == "Schema Org"
        assert tenant.slug == "schema-org"
        assert tenant.schema_mode == "schema"
        assert tenant.status == "initialized"

        # Verify schemas were created in the platform DB
        prefixes = TenantPrefix.all_prefixes(tenant.id)

        for {_key, prefix} <- prefixes do
          {:ok, result} = PlatformRepo.query(
            "SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1",
            [prefix]
          )
          assert result.num_rows == 1, "Expected schema '#{prefix}' to exist"
        end

        # Verify CA tables exist in the tenant CA schema
        {:ok, result} = PlatformRepo.query(
          "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY table_name",
          [prefixes.ca_prefix]
        )
        table_names = Enum.map(result.rows, fn [name] -> name end)
        assert "ca_instances" in table_names
        assert "issuer_keys" in table_names
        assert "keystores" in table_names

        # Verify RA tables exist in the tenant RA schema
        {:ok, result} = PlatformRepo.query(
          "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY table_name",
          [prefixes.ra_prefix]
        )
        table_names = Enum.map(result.rows, fn [name] -> name end)
        assert "csr_requests" in table_names
        assert "cert_profiles" in table_names
      after
        cleanup_tenant(tenant)
      end
    end

    test "delete removes schemas from shared DB" do
      {:ok, tenant} = Provisioner.create_tenant("Del Schema", "del-schema", email: "test@example.com")
      prefixes = TenantPrefix.all_prefixes(tenant.id)

      {:ok, _} = Provisioner.delete_tenant(tenant.id)

      # Schemas should be gone
      for {_key, prefix} <- prefixes do
        {:ok, result} = PlatformRepo.query(
          "SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1",
          [prefix]
        )
        assert result.num_rows == 0, "Expected schema '#{prefix}' to be dropped"
      end

      assert Provisioner.get_tenant(tenant.id) == nil
    end
  end

  # ── Database-mode provisioning (legacy) ───────────────────────────────
  # Tests below hardcode Postgres port 5434 (the old multi-instance
  # dev setup). Native PG on 5432 is the new baseline, so tag these
  # as :legacy_db_mode and exclude by default in test_helper.exs.

  describe "create_tenant/3 (database mode)" do
    @describetag :legacy_db_mode

    test "creates database, schemas, and inserts tenant record" do
      {:ok, tenant} = Provisioner.create_tenant("DB Org", "db-org",
        email: "test@example.com", schema_mode: "database")

      try do
        assert tenant.schema_mode == "database"
        assert tenant.database_name =~ ~r/^pki_tenant_[a-f0-9]+$/

        assert PlatformRepo.get(PkiPlatformEngine.Tenant, tenant.id) != nil
      after
        cleanup_tenant(tenant)
      end
    end

    test "creates all 3 schemas (ca, ra, audit)" do
      {:ok, tenant} = Provisioner.create_tenant("DB Schema Test", "db-schema-test",
        email: "test@example.com", schema_mode: "database")

      try do
        for schema <- ["ca", "ra", "audit"] do
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

    test "delete drops database and removes tenant record" do
      {:ok, tenant} = Provisioner.create_tenant("DB Del Test", "db-del-test",
        email: "test@example.com", schema_mode: "database")
      db_name = tenant.database_name

      {:ok, _} = Provisioner.delete_tenant(tenant.id)

      assert Provisioner.get_tenant(tenant.id) == nil

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
  end

  # ── Shared behavior ───────────────────────────────────────────────────

  describe "create_tenant/3 (validation)" do
    test "returns changeset error for duplicate slug without side effects" do
      {:ok, tenant} = Provisioner.create_tenant("First Org", "dup-slug", email: "test@example.com")

      try do
        {:error, changeset} = Provisioner.create_tenant("Second Org", "dup-slug", email: "test2@example.com")
        assert %{slug: ["has already been taken"]} = errors_on(changeset)
      after
        cleanup_tenant(tenant)
      end
    end

    test "returns changeset error for invalid slug" do
      {:error, changeset} = Provisioner.create_tenant("Bad Slug", "INVALID!", email: "test@example.com")
      assert %{slug: _} = errors_on(changeset)
    end

    test "returns changeset error for missing name" do
      {:error, changeset} = Provisioner.create_tenant(nil, "valid-slug", email: "test@example.com")
      assert %{name: ["can't be blank"]} = errors_on(changeset)
    end
  end

  describe "list_tenants/0" do
    test "returns all tenants ordered by inserted_at desc" do
      {:ok, t1} = Provisioner.create_tenant("List Org A", "list-org-a", email: "test@example.com")
      {:ok, t2} = Provisioner.create_tenant("List Org B", "list-org-b", email: "test2@example.com")

      try do
        tenants = Provisioner.list_tenants()
        slugs = Enum.map(tenants, & &1.slug)
        assert "list-org-a" in slugs
        assert "list-org-b" in slugs
        assert length(tenants) >= 2
      after
        cleanup_tenant(t2)
        cleanup_tenant(t1)
      end
    end
  end

  describe "get_tenant/1 and get_tenant_by_slug/1" do
    test "get_tenant returns tenant by id" do
      {:ok, tenant} = Provisioner.create_tenant("Get Test", "get-test", email: "test@example.com")

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
      {:ok, tenant} = Provisioner.create_tenant("Slug Test", "slug-test", email: "test@example.com")

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
      {:ok, tenant} = Provisioner.create_tenant("Suspend Test", "suspend-test", email: "test@example.com")

      try do
        {:ok, suspended} = Provisioner.suspend_tenant(tenant.id)
        assert suspended.status == "suspended"

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
      {:ok, tenant} = Provisioner.create_tenant("Activate Test", "activate-test", email: "test@example.com")

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
    test "returns error for unknown tenant" do
      assert {:error, :not_found} = Provisioner.delete_tenant(Uniq.UUID.uuid7())
    end

    test "beam-mode: deletes the row without touching a (non-existent) DB" do
      # Insert a beam-mode tenant directly (bypasses create_tenant's
      # schema/database paths; beam tenants have no per-tenant DB).
      {:ok, tenant} =
        %PkiPlatformEngine.Tenant{}
        |> PkiPlatformEngine.Tenant.changeset(%{
          name: "Beam Co #{System.unique_integer([:positive])}",
          slug: "beamco#{System.unique_integer([:positive])}",
          email: "beam@example.test",
          schema_mode: "beam",
          status: "active"
        })
        |> PlatformRepo.insert()

      assert {:ok, %PkiPlatformEngine.Tenant{}} = Provisioner.delete_tenant(tenant.id)
      assert PlatformRepo.get(PkiPlatformEngine.Tenant, tenant.id) == nil
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
