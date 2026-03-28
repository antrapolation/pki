defmodule PkiPlatformEngine.TenantRepoTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.TenantRepo

  @test_db "pki_tenant_repo_test"

  setup_all do
    # Create a temporary test database
    {:ok, conn} = Postgrex.start_link(
      hostname: "localhost",
      port: 5434,
      username: "postgres",
      password: "postgres",
      database: "postgres"
    )

    # Drop if leftover from a previous failed run
    Postgrex.query(conn, "DROP DATABASE IF EXISTS #{@test_db}", [])
    {:ok, _} = Postgrex.query(conn, "CREATE DATABASE #{@test_db}", [])
    GenServer.stop(conn)

    # Set up schemas and tables in the test database
    {:ok, tenant_conn} = Postgrex.start_link(
      hostname: "localhost",
      port: 5434,
      username: "postgres",
      password: "postgres",
      database: @test_db
    )

    Postgrex.query!(tenant_conn, "CREATE SCHEMA IF NOT EXISTS ca", [])
    Postgrex.query!(tenant_conn, "CREATE SCHEMA IF NOT EXISTS ra", [])

    Postgrex.query!(tenant_conn, """
    CREATE TABLE ca.users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'admin'
    )
    """, [])

    Postgrex.query!(tenant_conn, """
    CREATE TABLE ra.users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'officer'
    )
    """, [])

    Postgrex.query!(tenant_conn, "INSERT INTO ca.users (name, role) VALUES ('Alice', 'ca_admin')", [])
    Postgrex.query!(tenant_conn, "INSERT INTO ca.users (name, role) VALUES ('Bob', 'key_manager')", [])
    Postgrex.query!(tenant_conn, "INSERT INTO ra.users (name, role) VALUES ('Charlie', 'ra_admin')", [])

    GenServer.stop(tenant_conn)

    on_exit(fn ->
      {:ok, conn} = Postgrex.start_link(
        hostname: "localhost",
        port: 5434,
        username: "postgres",
        password: "postgres",
        database: "postgres"
      )

      Postgrex.query(conn, "DROP DATABASE IF EXISTS #{@test_db}", [])
      GenServer.stop(conn)
    end)

    :ok
  end

  describe "execute_sql/4" do
    test "executes SQL against the tenant database" do
      {:ok, result} = TenantRepo.execute_sql(@test_db, "public", "SELECT 1 AS num", [])
      assert result.num_rows == 1
      assert result.rows == [[1]]
    end

    test "queries ca schema tables" do
      {:ok, result} = TenantRepo.execute_sql(
        @test_db, "ca",
        "SELECT name, role FROM users ORDER BY name", []
      )

      assert result.num_rows == 2
      assert result.rows == [["Alice", "ca_admin"], ["Bob", "key_manager"]]
    end

    test "queries ra schema tables" do
      {:ok, result} = TenantRepo.execute_sql(
        @test_db, "ra",
        "SELECT name, role FROM users ORDER BY name", []
      )

      assert result.num_rows == 1
      assert result.rows == [["Charlie", "ra_admin"]]
    end

    test "schema prefix isolates ca from ra" do
      {:ok, ca_result} = TenantRepo.execute_sql(
        @test_db, "ca", "SELECT count(*) FROM users", []
      )

      {:ok, ra_result} = TenantRepo.execute_sql(
        @test_db, "ra", "SELECT count(*) FROM users", []
      )

      assert ca_result.rows == [[2]]
      assert ra_result.rows == [[1]]
    end

    test "returns error for nonexistent table" do
      assert {:error, %Postgrex.Error{}} = TenantRepo.execute_sql(
        @test_db, "ca", "SELECT * FROM nonexistent_table", []
      )
    end

    test "accepts a Tenant struct" do
      tenant = %PkiPlatformEngine.Tenant{
        id: "test-id",
        database_name: @test_db,
        name: "Test",
        slug: "test"
      }

      {:ok, result} = TenantRepo.execute_sql(tenant, "ca", "SELECT count(*) FROM users", [])
      assert result.rows == [[2]]
    end
  end

  describe "with_tenant/3" do
    test "executes function in tenant context and returns result" do
      result = TenantRepo.with_tenant(@test_db, "ca", fn ->
        TenantRepo.query!("SELECT name FROM users ORDER BY name")
      end)

      assert result.num_rows == 2
      assert result.rows == [["Alice"], ["Bob"]]
    end

    test "switches schema prefix correctly" do
      ca_result = TenantRepo.with_tenant(@test_db, "ca", fn ->
        TenantRepo.query!("SELECT count(*) FROM users")
      end)

      ra_result = TenantRepo.with_tenant(@test_db, "ra", fn ->
        TenantRepo.query!("SELECT count(*) FROM users")
      end)

      assert ca_result.rows == [[2]]
      assert ra_result.rows == [[1]]
    end

    test "accepts a Tenant struct" do
      tenant = %PkiPlatformEngine.Tenant{
        id: "test-id",
        database_name: @test_db,
        name: "Test",
        slug: "test"
      }

      result = TenantRepo.with_tenant(tenant, "ra", fn ->
        TenantRepo.query!("SELECT name FROM users")
      end)

      assert result.rows == [["Charlie"]]
    end

    test "can write and read data within tenant context" do
      TenantRepo.with_tenant(@test_db, "ra", fn ->
        TenantRepo.query!("INSERT INTO users (name, role) VALUES ('Dave', 'auditor')")
      end)

      result = TenantRepo.with_tenant(@test_db, "ra", fn ->
        TenantRepo.query!("SELECT name FROM users WHERE role = 'auditor'")
      end)

      assert result.rows == [["Dave"]]

      # Clean up
      TenantRepo.with_tenant(@test_db, "ra", fn ->
        TenantRepo.query!("DELETE FROM users WHERE name = 'Dave'")
      end)
    end

    test "cleans up dynamic repo after execution" do
      _result = TenantRepo.with_tenant(@test_db, "ca", fn ->
        TenantRepo.query!("SELECT 1")
      end)

      # After with_tenant, the dynamic repo should be restored to the module default.
      # Calling query outside with_tenant should fail because the default repo is not started.
      assert_raise RuntimeError, ~r/could not lookup Ecto repo/, fn ->
        TenantRepo.query!("SELECT 1")
      end
    end
  end

  describe "validation" do
    test "rejects invalid schema prefix in with_tenant" do
      assert_raise FunctionClauseError, fn ->
        TenantRepo.with_tenant(@test_db, "invalid_schema", fn -> :ok end)
      end
    end

    test "rejects invalid schema prefix in execute_sql" do
      assert_raise FunctionClauseError, fn ->
        TenantRepo.execute_sql(@test_db, "invalid_schema", "SELECT 1", [])
      end
    end
  end
end
