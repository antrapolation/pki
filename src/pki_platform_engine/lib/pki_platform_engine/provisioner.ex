defmodule PkiPlatformEngine.Provisioner do
  @moduledoc """
  Provisions and manages tenant databases/schemas.

  Supports two modes:
  - **schema mode** (default for new tenants): Creates PostgreSQL schemas in the
    shared platform database and runs Ecto migrations with `prefix:`.
  - **database mode** (legacy): Creates a dedicated database per tenant with raw SQL.
  """

  alias PkiPlatformEngine.{PlatformRepo, Tenant, TenantPrefix, TenantRepo}
  import Ecto.Query

  require Logger

  @doc """
  Per-tenant BEAM registration: inserts a `Tenant` row in the platform
  DB with status `"provisioning"`. No Postgres schema creation — tenant
  state lives in Mnesia on the spawned BEAM. Used by
  `TenantOnboarding.register_tenant/3`.
  """
  @spec register_tenant(String.t(), String.t(), keyword()) ::
          {:ok, Tenant.t()} | {:error, Ecto.Changeset.t() | term()}
  def register_tenant(name, slug, opts \\ []) do
    attrs = %{
      name: name,
      slug: slug,
      email: Keyword.get(opts, :email),
      schema_mode: "beam",
      status: "provisioning"
    }

    %Tenant{}
    |> Tenant.changeset(attrs)
    |> PlatformRepo.insert()
  end

  def create_tenant(name, slug, opts \\ []) do
    schema_mode = Keyword.get(opts, :schema_mode, "schema")

    attrs = %{
      name: name,
      slug: slug,
      email: Keyword.get(opts, :email),
      schema_mode: schema_mode
    }

    changeset = Tenant.changeset(%Tenant{}, attrs)

    case Ecto.Changeset.apply_action(changeset, :validate) do
      {:ok, _tenant_data} ->
        case schema_mode do
          "schema" -> create_schema_mode_tenant(changeset)
          "database" -> create_database_mode_tenant(changeset)
        end

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def suspend_tenant(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil ->
        {:error, :not_found}

      tenant ->
        PkiPlatformEngine.TenantSupervisor.stop_tenant(tenant_id)

        tenant
        |> Tenant.status_changeset(%{status: "suspended"})
        |> PlatformRepo.update()
    end
  end

  def activate_tenant(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil ->
        {:error, :not_found}

      tenant ->
        case PkiPlatformEngine.TenantSupervisor.start_tenant(tenant) do
          {:ok, _} ->
            tenant
            |> Tenant.status_changeset(%{status: "active"})
            |> PlatformRepo.update()

          {:error, reason} ->
            {:error, {:engine_start_failed, reason}}
        end
    end
  end

  def update_tenant(tenant_id, attrs) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil -> {:error, :not_found}
      tenant -> tenant |> Tenant.changeset(attrs) |> PlatformRepo.update()
    end
  end

  def delete_tenant(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil ->
        {:error, :not_found}

      %{schema_mode: "schema"} = tenant ->
        result = delete_schema_mode_tenant(tenant)
        _ = PkiPlatformEngine.SofthsmTokenManager.cleanup_tenant_token(tenant.slug)
        result

      %{schema_mode: "beam"} = tenant ->
        result = delete_beam_mode_tenant(tenant)
        _ = PkiPlatformEngine.SofthsmTokenManager.cleanup_tenant_token(tenant.slug)
        result

      tenant ->
        result = delete_database_mode_tenant(tenant)
        _ = PkiPlatformEngine.SofthsmTokenManager.cleanup_tenant_token(tenant.slug)
        result
    end
  end

  def list_tenants do
    PlatformRepo.all(from t in Tenant, order_by: [desc: t.inserted_at])
  end

  def get_tenant(id), do: PlatformRepo.get(Tenant, id)
  def get_tenant_by_slug(slug), do: PlatformRepo.get_by(Tenant, slug: slug)

  @doc "Returns true only if the tenant exists and has status \"active\"."
  def tenant_active?(tenant_id) do
    case get_tenant(tenant_id) do
      %{status: "active"} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  # ── Schema-mode provisioning ──────────────────────────────────────────

  defp create_schema_mode_tenant(changeset) do
    tenant_id = Ecto.Changeset.get_field(changeset, :id)
    prefixes = TenantPrefix.all_prefixes(tenant_id)

    Logger.info("tenant_provisioning tenant_id=#{tenant_id} step=insert")

    with {:ok, tenant} <- PlatformRepo.insert(changeset),
         _ = Logger.info("tenant_provisioning tenant_id=#{tenant_id} step=create_schemas"),
         :ok <- create_tenant_schemas(prefixes),
         _ = Logger.info("tenant_provisioning tenant_id=#{tenant_id} step=run_migrations"),
         :ok <- run_tenant_migrations(prefixes) do
      Logger.info("tenant_provisioning tenant_id=#{tenant_id} step=complete")
      {:ok, tenant}
    else
      {:error, %Ecto.Changeset{} = cs} ->
        {:error, cs}

      {:error, reason} ->
        Logger.error("tenant_provisioning_failed tenant_id=#{tenant_id} reason=#{inspect(reason)}, cleaning up...")
        cleanup_failed_provisioning(tenant_id, prefixes)
        {:error, reason}
    end
  end

  defp cleanup_failed_provisioning(tenant_id, prefixes) do
    try do
      PlatformRepo.delete_all(from t in Tenant, where: t.id == ^tenant_id)
    rescue
      e -> Logger.error("cleanup_db_record_failed tenant_id=#{tenant_id} error=#{Exception.message(e)}")
    end

    try do
      drop_tenant_schemas(prefixes)
    rescue
      e -> Logger.error("cleanup_schemas_failed tenant_id=#{tenant_id} error=#{Exception.message(e)}")
    end
  end

  defp create_tenant_schemas(prefixes) do
    # Use direct Postgrex connection so schemas are committed immediately.
    # Ecto.Migrator bypasses Sandbox, so it needs actually-committed schemas.
    with_platform_conn(fn conn ->
      Enum.reduce_while(prefixes, :ok, fn {_key, prefix}, :ok ->
        case Postgrex.query(conn, "CREATE SCHEMA IF NOT EXISTS \"#{TenantPrefix.validate_prefix!(prefix)}\"", []) do
          {:ok, _} -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, {:schema_creation_failed, prefix, reason}}}
        end
      end)
    end)
  end

  defp run_tenant_migrations(prefixes) do
    # Apply the raw tenant schema SQL files with the literal source schema
    # prefixes rewritten to the tenant-specific dynamic schema.
    # The engine Ecto migrations were removed in df729af; these SQL files
    # in priv/ are now the authoritative source for tenant schemas.
    try do
      Logger.info("tenant_migration_start prefix=#{prefixes.ca_prefix} engine=ca")
      apply_tenant_schema_sql("tenant_ca_schema.sql", "ca", prefixes.ca_prefix)
      Logger.info("tenant_migration_done prefix=#{prefixes.ca_prefix} engine=ca")

      Logger.info("tenant_migration_start prefix=#{prefixes.ra_prefix} engine=ra")
      apply_tenant_schema_sql("tenant_ra_schema.sql", "ra", prefixes.ra_prefix)
      Logger.info("tenant_migration_done prefix=#{prefixes.ra_prefix} engine=ra")

      Logger.info("tenant_migration_start prefix=#{prefixes.audit_prefix} engine=audit")
      apply_tenant_schema_sql("tenant_audit_schema.sql", "audit", prefixes.audit_prefix)
      Logger.info("tenant_migration_done prefix=#{prefixes.audit_prefix} engine=audit")

      Logger.info("tenant_migration_start prefix=#{prefixes.validation_prefix} engine=validation")
      apply_tenant_schema_sql("tenant_validation_schema.sql", "validation", prefixes.validation_prefix)
      Logger.info("tenant_migration_done prefix=#{prefixes.validation_prefix} engine=validation")

      :ok
    rescue
      e ->
        Logger.error("tenant_migration_failed error=#{Exception.message(e)}")
        {:error, {:migration_failed, Exception.message(e)}}
    end
  end

  @doc "Public: run a single schema SQL file against a target prefix. Idempotent (uses IF NOT EXISTS)."
  def apply_schema_sql(filename, source_schema, target_prefix) do
    apply_tenant_schema_sql(filename, source_schema, target_prefix)
  end

  @doc "Public: create a schema if it does not already exist."
  def ensure_schema_exists(prefix) do
    safe = TenantPrefix.validate_prefix!(prefix)
    with_platform_conn(fn conn ->
      case Postgrex.query(conn, "CREATE SCHEMA IF NOT EXISTS \"#{safe}\"", []) do
        {:ok, _} -> :ok
        {:error, reason} -> raise "ensure_schema_exists failed for #{prefix}: #{inspect(reason)}"
      end
    end)
  end

  defp apply_tenant_schema_sql(filename, source_schema, target_prefix) do
    safe_prefix = TenantPrefix.validate_prefix!(target_prefix)

    sql =
      "tenant_schema_sql"
      |> read_schema_sql_file(filename)
      |> rewrite_schema_prefix(source_schema, safe_prefix)

    with_platform_conn(fn conn ->
      # Split on semicolons and run each non-empty statement.
      sql
      |> String.split(";")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.reduce_while(:ok, fn stmt, :ok ->
        case Postgrex.query(conn, stmt, []) do
          {:ok, _} -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
    end)
    |> case do
      :ok -> :ok
      {:error, reason} -> raise "apply_tenant_schema_sql failed: #{inspect(reason)}"
    end
  end

  defp read_schema_sql_file(_tag, filename) do
    priv_dir = :code.priv_dir(:pki_platform_engine)
    File.read!(Path.join(priv_dir, filename))
  end

  defp rewrite_schema_prefix(sql, source, target) do
    # 1. Drop "CREATE SCHEMA IF NOT EXISTS <source>;" — target already exists.
    # 2. Rewrite "<source>." qualified identifiers to "<target>.".
    sql
    |> String.replace(~r/CREATE\s+SCHEMA\s+IF\s+NOT\s+EXISTS\s+#{source}\s*;/i, "")
    |> String.replace(~r/\b#{source}\./, "\"#{target}\".")
  end

  defp platform_repo_config do
    config = Application.get_env(:pki_platform_engine, PlatformRepo, [])
    # Strip sandbox pool — use standard Postgrex pool for migrations
    config
    |> Keyword.delete(:pool)
    |> Keyword.put_new(:pool_size, 2)
  end

  defp drop_tenant_schemas(prefixes) do
    with_platform_conn(fn conn ->
      for {_key, prefix} <- prefixes do
        Postgrex.query(conn, "DROP SCHEMA IF EXISTS \"#{TenantPrefix.validate_prefix!(prefix)}\" CASCADE", [])
      end
      :ok
    end)
  end

  defp delete_schema_mode_tenant(tenant) do
    PkiPlatformEngine.TenantSupervisor.stop_tenant(tenant.id)
    prefixes = TenantPrefix.all_prefixes(tenant.id)

    case PlatformRepo.delete(tenant) do
      {:ok, deleted} ->
        drop_tenant_schemas(prefixes)
        {:ok, deleted}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Direct connection to the platform database (not through Ecto Sandbox).
  defp with_platform_conn(fun) do
    config = Application.get_env(:pki_platform_engine, PlatformRepo, [])
    {hostname, port, username, password} = parse_conn_config(config)

    database = case Keyword.get(config, :url) do
      nil -> Keyword.get(config, :database, "pki_platform_engine_dev")
      url -> URI.parse(url).path |> String.trim_leading("/")
    end

    case Postgrex.start_link(
           hostname: hostname,
           port: port,
           username: username,
           password: password,
           database: database
         ) do
      {:ok, conn} ->
        try do
          fun.(conn)
        after
          GenServer.stop(conn)
        end

      {:error, reason} ->
        {:error, {:platform_conn_failed, reason}}
    end
  end

  # ── Database-mode provisioning (legacy) ───────────────────────────────

  defp create_database_mode_tenant(changeset) do
    db_name = Ecto.Changeset.get_field(changeset, :database_name)

    with :ok <- create_database(db_name),
         :ok <- create_tenant_tables(db_name),
         {:ok, tenant} <- PlatformRepo.insert(changeset) do
      PkiPlatformEngine.TenantMigrator.migrate_tenant(tenant.id, db_name)
      {:ok, tenant}
    else
      {:error, reason} ->
        drop_database(db_name)
        {:error, reason}
    end
  end

  defp delete_database_mode_tenant(tenant) do
    PkiPlatformEngine.TenantSupervisor.stop_tenant(tenant.id)

    case PlatformRepo.delete(tenant) do
      {:ok, deleted} ->
        drop_database(deleted.database_name)
        {:ok, deleted}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # BEAM-mode tenants have no per-tenant Postgres database and no
  # schema prefixes — their state is a per-tenant Mnesia dir managed
  # by the spawned peer. TenantSupervisor.stop_tenant routes to
  # TenantLifecycle.stop_tenant, which gracefully stops the peer,
  # releases the port (incl. its `tenant_port_assignments` row), and
  # removes the Caddy route. After that, deleting the platform-DB
  # row is all that's left.
  defp delete_beam_mode_tenant(tenant) do
    _ = PkiPlatformEngine.TenantSupervisor.stop_tenant(tenant.id)

    case PlatformRepo.delete(tenant) do
      {:ok, deleted} -> {:ok, deleted}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── Migration paths ───────────────────────────────────────────────────

  # ── Database-mode helpers (unchanged) ─────────────────────────────────

  defp validate_db_name!(db_name) do
    unless db_name =~ ~r/\Apki_tenant_[0-9a-f]{32}\z/ do
      raise ArgumentError, "Invalid database name: #{inspect(db_name)}"
    end

    db_name
  end

  defp with_admin_conn(fun) do
    config = Application.get_env(:pki_platform_engine, PlatformRepo, [])
    {hostname, port, username, password} = parse_conn_config(config)

    case Postgrex.start_link(
           hostname: hostname,
           port: port,
           username: username,
           password: password,
           database: "postgres"
         ) do
      {:ok, conn} ->
        try do
          fun.(conn)
        after
          GenServer.stop(conn)
        end

      {:error, reason} ->
        {:error, {:admin_conn_failed, reason}}
    end
  end

  defp parse_conn_config(config) do
    case Keyword.get(config, :url) do
      nil ->
        {
          Keyword.get(config, :hostname, "localhost"),
          Keyword.get(config, :port, 5432),
          Keyword.get(config, :username, "postgres"),
          Keyword.get(config, :password, "postgres")
        }

      url ->
        uri = URI.parse(url)
        userinfo = String.split(uri.userinfo || "postgres:postgres", ":", parts: 2)
        {
          uri.host || "localhost",
          uri.port || 5432,
          Enum.at(userinfo, 0, "postgres"),
          Enum.at(userinfo, 1, "postgres") |> URI.decode()
        }
    end
  end

  defp create_database(db_name) do
    safe = validate_db_name!(db_name)

    with_admin_conn(fn conn ->
      case Postgrex.query(conn, "CREATE DATABASE \"#{safe}\"", []) do
        {:ok, _} -> :ok
        {:error, %{postgres: %{code: :duplicate_database}}} -> :ok
        {:error, reason} -> {:error, {:create_database_failed, reason}}
      end
    end)
  end

  defp create_tenant_tables(db_name) do
    safe = validate_db_name!(db_name)

    ca_sql = read_schema_sql("tenant_ca_schema.sql")
    case apply_schema_sql(safe, ca_sql) do
      :ok -> :ok
      {:error, reason} -> throw {:error, {:ca_schema_failed, reason}}
    end

    ra_sql = read_schema_sql("tenant_ra_schema.sql")
    case apply_schema_sql(safe, ra_sql) do
      :ok -> :ok
      {:error, reason} -> throw {:error, {:ra_schema_failed, reason}}
    end

    for schema <- ["validation", "audit"] do
      case apply_schema_sql(safe, "CREATE SCHEMA IF NOT EXISTS #{schema}") do
        :ok -> :ok
        {:error, reason} -> throw {:error, {:"#{schema}_schema_failed", reason}}
      end
    end

    :ok
  catch
    {:error, reason} -> {:error, reason}
  end

  defp read_schema_sql(filename) do
    priv_dir = :code.priv_dir(:pki_platform_engine)
    path = Path.join(priv_dir, filename)
    File.read!(path)
  end

  defp apply_schema_sql(db_name, sql) do
    config = Application.get_env(:pki_platform_engine, TenantRepo, [])
    {hostname, port, username, password} = parse_conn_config(config)

    case Postgrex.start_link(
           hostname: hostname,
           port: port,
           username: username,
           password: password,
           database: db_name
         ) do
      {:ok, conn} ->
        try do
          statements =
            sql
            |> String.split(";")
            |> Enum.map(&String.trim/1)
            |> Enum.reject(&(&1 == ""))

          Enum.reduce_while(statements, :ok, fn stmt, :ok ->
            case Postgrex.query(conn, stmt, []) do
              {:ok, _} ->
                {:cont, :ok}

              {:error, %{postgres: %{code: code}}}
              when code in [:duplicate_table, :duplicate_object, :duplicate_column, :invalid_table_definition] ->
                {:cont, :ok}

              {:error, reason} ->
                {:halt, {:error, reason}}
            end
          end)
        after
          GenServer.stop(conn)
        end

      {:error, reason} ->
        {:error, {:connection_failed, reason}}
    end
  end

  defp drop_database(db_name) do
    safe = validate_db_name!(db_name)

    with_admin_conn(fn conn ->
      Postgrex.query(conn, "DROP DATABASE IF EXISTS \"#{safe}\" WITH (FORCE)", [])
      :ok
    end)
  rescue
    _ -> :ok
  end
end
