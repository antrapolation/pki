defmodule PkiRaEngine.MultiTenantTest do
  @moduledoc """
  Multi-tenant integration tests — verifies that tenant isolation works correctly.

  Creates a separate PostgreSQL schema for a test tenant, starts a DynamicRepo
  pointing to it, registers it in TenantRegistry, and verifies that data written
  in one tenant context is not visible in another.
  """
  use PkiRaEngine.DataCase, async: false

  alias PkiRaEngine.CsrValidation
  alias PkiRaEngine.CertProfileConfig
  alias PkiRaEngine.UserManagement
  alias PkiRaEngine.ApiKeyManagement

  @tenant_id "test-tenant-isolation"
  @schema_prefix "ra_test_tenant"

  setup do
    # 1. Create the tenant schema OUTSIDE the sandbox (DDL needs to be visible to DynamicRepo)
    create_tenant_schema_outside_sandbox!()

    # 2. Start TenantRegistry if not already running
    ensure_registry_started!()

    # 3. Start a DynamicRepo instance for the test tenant
    # Use a unique name per test to avoid conflicts
    suffix = System.unique_integer([:positive])
    repo_name = :"ra_repo_test_#{suffix}"
    db_config = Application.get_env(:pki_ra_engine, PkiRaEngine.Repo)

    dynamic_config = [
      name: repo_name,
      username: db_config[:username],
      password: db_config[:password],
      hostname: db_config[:hostname],
      port: db_config[:port],
      database: db_config[:database],
      pool_size: 5,
      after_connect: {Postgrex, :query!, ["SET search_path TO #{@schema_prefix}", []]}
    ]

    _pid = start_supervised!({PkiPlatformEngine.DynamicRepo, dynamic_config}, id: repo_name)

    # 4. Register the tenant in the registry
    PkiPlatformEngine.TenantRegistry.register(@tenant_id, %{
      ra_repo: repo_name,
      slug: "test-tenant-#{suffix}"
    })

    on_exit(fn ->
      PkiPlatformEngine.TenantRegistry.unregister(@tenant_id)
      # Clean up tenant data via raw connection
      cleanup_tenant_data_outside_sandbox!()
    end)

    :ok
  end

  # ── User isolation ────────────────────────────────────────────────

  describe "user isolation between tenants" do
    test "users created in default tenant are not visible in test tenant" do
      # Create user in default tenant (nil)
      {:ok, default_user} = UserManagement.create_user(nil, %{
        display_name: "Default Tenant User",
        role: "ra_admin"
      })

      # Create user in test tenant
      {:ok, tenant_user} = UserManagement.create_user(@tenant_id, %{
        display_name: "Test Tenant User",
        role: "ra_officer"
      })

      # List users in default tenant — should only see default user
      default_users = UserManagement.list_users(nil, [])
      default_ids = Enum.map(default_users, & &1.id)
      assert default_user.id in default_ids
      refute tenant_user.id in default_ids

      # List users in test tenant — should only see tenant user
      tenant_users = UserManagement.list_users(@tenant_id, [])
      tenant_ids = Enum.map(tenant_users, & &1.id)
      assert tenant_user.id in tenant_ids
      refute default_user.id in tenant_ids
    end

    test "get_user in wrong tenant returns not_found" do
      {:ok, user} = UserManagement.create_user(nil, %{
        display_name: "Default Only",
        role: "ra_admin"
      })

      # Should find in default tenant
      assert {:ok, _} = UserManagement.get_user(nil, user.id)

      # Should NOT find in test tenant
      assert {:error, :not_found} = UserManagement.get_user(@tenant_id, user.id)
    end
  end

  # ── CSR isolation ──────────────────────────────────────────────────

  describe "CSR isolation between tenants" do
    test "CSRs created in one tenant are not visible in another" do
      # Create profiles in each tenant
      {:ok, default_profile} = CertProfileConfig.create_profile(nil, %{
        name: "default_profile_#{System.unique_integer([:positive])}"
      })
      {:ok, tenant_profile} = CertProfileConfig.create_profile(@tenant_id, %{
        name: "tenant_profile_#{System.unique_integer([:positive])}"
      })

      # Submit CSRs in each tenant
      csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBmulti\n-----END CERTIFICATE REQUEST-----"
      {:ok, default_csr} = CsrValidation.submit_csr(nil, csr_pem, default_profile.id)
      {:ok, tenant_csr} = CsrValidation.submit_csr(@tenant_id, csr_pem, tenant_profile.id)

      # List CSRs in default tenant
      default_csrs = CsrValidation.list_csrs(nil, [])
      default_csr_ids = Enum.map(default_csrs, & &1.id)
      assert default_csr.id in default_csr_ids
      refute tenant_csr.id in default_csr_ids

      # List CSRs in test tenant
      tenant_csrs = CsrValidation.list_csrs(@tenant_id, [])
      tenant_csr_ids = Enum.map(tenant_csrs, & &1.id)
      assert tenant_csr.id in tenant_csr_ids
      refute default_csr.id in tenant_csr_ids
    end

    test "get_csr in wrong tenant returns not_found" do
      {:ok, profile} = CertProfileConfig.create_profile(nil, %{
        name: "isolation_profile_#{System.unique_integer([:positive])}"
      })

      csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBiso\n-----END CERTIFICATE REQUEST-----"
      {:ok, csr} = CsrValidation.submit_csr(nil, csr_pem, profile.id)

      assert {:ok, _} = CsrValidation.get_csr(nil, csr.id)
      assert {:error, :not_found} = CsrValidation.get_csr(@tenant_id, csr.id)
    end
  end

  # ── Cert profile isolation ────────────────────────────────────────

  describe "cert profile isolation between tenants" do
    test "profiles in one tenant are not visible in another" do
      {:ok, default_profile} = CertProfileConfig.create_profile(nil, %{
        name: "default_prof_#{System.unique_integer([:positive])}"
      })
      {:ok, tenant_profile} = CertProfileConfig.create_profile(@tenant_id, %{
        name: "tenant_prof_#{System.unique_integer([:positive])}"
      })

      default_profiles = CertProfileConfig.list_profiles(nil)
      default_ids = Enum.map(default_profiles, & &1.id)
      assert default_profile.id in default_ids
      refute tenant_profile.id in default_ids

      tenant_profiles = CertProfileConfig.list_profiles(@tenant_id)
      tenant_ids = Enum.map(tenant_profiles, & &1.id)
      assert tenant_profile.id in tenant_ids
      refute default_profile.id in tenant_ids
    end
  end

  # ── API key isolation ─────────────────────────────────────────────

  describe "API key isolation between tenants" do
    test "API keys created in one tenant cannot be verified in another" do
      {:ok, user} = UserManagement.create_user(nil, %{
        display_name: "Key Test User",
        role: "ra_admin"
      })

      {:ok, %{raw_key: raw_key}} = ApiKeyManagement.create_api_key(nil, %{
        ra_user_id: user.id,
        label: "isolation_test"
      })

      # Should verify in default tenant
      assert {:ok, _} = ApiKeyManagement.verify_key(nil, raw_key)

      # Should NOT verify in test tenant (key doesn't exist there)
      assert {:error, :invalid_key} = ApiKeyManagement.verify_key(@tenant_id, raw_key)
    end
  end

  # ── Helpers ────────────────────────────────────────────────────────

  defp ensure_registry_started! do
    case Process.whereis(PkiPlatformEngine.TenantRegistry) do
      nil -> start_supervised!(PkiPlatformEngine.TenantRegistry)
      _pid -> :ok
    end
  end

  defp cleanup_tenant_data_outside_sandbox! do
    db_config = Application.get_env(:pki_ra_engine, PkiRaEngine.Repo)

    {:ok, conn} = Postgrex.start_link(
      hostname: db_config[:hostname],
      port: db_config[:port],
      username: db_config[:username],
      password: db_config[:password],
      database: db_config[:database]
    )

    Postgrex.query(conn, "DROP SCHEMA IF EXISTS #{@schema_prefix} CASCADE", [])
    GenServer.stop(conn)
  rescue
    _ -> :ok
  end

  defp create_tenant_schema_outside_sandbox! do
    # Use a raw Postgrex connection (not sandbox) so DDL is visible to DynamicRepo
    db_config = Application.get_env(:pki_ra_engine, PkiRaEngine.Repo)

    {:ok, conn} = Postgrex.start_link(
      hostname: db_config[:hostname],
      port: db_config[:port],
      username: db_config[:username],
      password: db_config[:password],
      database: db_config[:database]
    )

    Postgrex.query!(conn, "CREATE SCHEMA IF NOT EXISTS #{@schema_prefix}", [])

    tables = [
      "ra_users", "cert_profiles", "ra_instances", "service_configs",
      "ra_api_keys", "csr_requests", "credentials", "dcv_challenges"
    ]

    for table <- tables do
      Postgrex.query!(conn, """
        CREATE TABLE IF NOT EXISTS #{@schema_prefix}.#{table}
        (LIKE public.#{table} INCLUDING DEFAULTS INCLUDING INDEXES)
      """, [])
    end

    GenServer.stop(conn)
  end
end
