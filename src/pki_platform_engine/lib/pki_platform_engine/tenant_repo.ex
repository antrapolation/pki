defmodule PkiPlatformEngine.TenantRepo do
  @moduledoc """
  Dynamic Ecto repo for per-tenant database access.

  Each tenant has its own PostgreSQL database. Within each database, schemas
  (ca, ra, validation, audit) provide namespace isolation for different services.

  ## Usage

      PkiPlatformEngine.TenantRepo.with_tenant("pki_tenant_abc123", "ca", fn ->
        PkiPlatformEngine.TenantRepo.all(SomeSchema)
      end)

  Or with a Tenant struct:

      PkiPlatformEngine.TenantRepo.with_tenant(tenant, "ra", fn ->
        PkiPlatformEngine.TenantRepo.insert(%RaUser{name: "alice"})
      end)

  For raw SQL:

      PkiPlatformEngine.TenantRepo.execute_sql("pki_tenant_abc123", "ca", "SELECT 1", [])
  """

  use Ecto.Repo,
    otp_app: :pki_platform_engine,
    adapter: Ecto.Adapters.Postgres

  @valid_prefixes ["ca", "ra", "validation", "audit", "public"]

  @doc """
  Execute a function in the context of a specific tenant's database.

  Starts a dynamic repo instance connected to the tenant's database with the
  given schema prefix, executes the function, then stops the instance.

  The function receives no arguments -- use `PkiPlatformEngine.TenantRepo` directly
  inside the function body, as `put_dynamic_repo/1` routes calls to the
  correct instance.

  ## Parameters

    * `tenant_or_db` - A `%PkiPlatformEngine.Tenant{}` struct or a database name string
    * `schema_prefix` - PostgreSQL schema: "ca", "ra", "validation", "audit", or "public"
    * `fun` - Zero-arity function to execute in the tenant context

  ## Examples

      TenantRepo.with_tenant("pki_tenant_abc123", "ca", fn ->
        TenantRepo.all(CaUser)
      end)
  """
  def with_tenant(%PkiPlatformEngine.Tenant{database_name: db_name}, schema_prefix, fun) do
    with_tenant(db_name, schema_prefix, fun)
  end

  def with_tenant(database_name, schema_prefix, fun)
      when is_binary(database_name) and schema_prefix in @valid_prefixes do
    config = build_config(database_name, schema_prefix)

    case __MODULE__.start_link(config) do
      {:ok, pid} ->
        previous = put_dynamic_repo(pid)
        try do
          {:ok, fun.()}
        catch
          kind, reason -> {:error, {kind, reason}}
        after
          put_dynamic_repo(previous)
          Supervisor.stop(pid, :normal, 5_000)
        end

      {:error, reason} ->
        {:error, {:connection_failed, reason}}
    end
  end

  @doc """
  Execute raw SQL against a tenant's database with schema isolation.

  Returns `{:ok, %Postgrex.Result{}}` or `{:error, %Postgrex.Error{}}`.

  ## Parameters

    * `tenant_or_db` - A `%PkiPlatformEngine.Tenant{}` struct or a database name string
    * `schema_prefix` - PostgreSQL schema: "ca", "ra", "validation", "audit", or "public"
    * `sql` - SQL string to execute
    * `params` - List of query parameters (default: [])
  """
  def execute_sql(tenant_or_db, schema_prefix, sql, params \\ [])

  def execute_sql(%PkiPlatformEngine.Tenant{database_name: db_name}, schema_prefix, sql, params) do
    execute_sql(db_name, schema_prefix, sql, params)
  end

  def execute_sql(database_name, schema_prefix, sql, params)
      when is_binary(database_name) and schema_prefix in @valid_prefixes do
    with_tenant(database_name, schema_prefix, fn ->
      __MODULE__.query(sql, params)
    end)
  end

  defp build_config(database_name, schema_prefix) when schema_prefix in @valid_prefixes do
    # Inherit connection details from PlatformRepo config (which has the DB URL)
    platform_config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.PlatformRepo, [])
    base = Application.get_env(:pki_platform_engine, __MODULE__, [])

    [
      hostname: Keyword.get(base, :hostname, Keyword.get(platform_config, :hostname, "localhost")),
      port: Keyword.get(base, :port, Keyword.get(platform_config, :port, 6432)),
      username: Keyword.get(base, :username, Keyword.get(platform_config, :username, "postgres")),
      password: Keyword.get(base, :password, Keyword.get(platform_config, :password, "postgres")),
      database: database_name,
      pool_size: Keyword.get(base, :pool_size, 2),
      connect_timeout: 5_000,
      prepare: :unnamed,
      after_connect: {Postgrex, :query!, ["SET search_path TO #{schema_prefix}", []]},
      name: nil
    ]
  end
end
