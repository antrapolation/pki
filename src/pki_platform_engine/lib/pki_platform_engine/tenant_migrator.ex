defmodule PkiPlatformEngine.TenantMigrator do
  @moduledoc """
  Automated tenant database migration system.

  Reads numbered SQL files from `priv/tenant_migrations/` and applies them
  to each active tenant database. Tracks applied versions in the platform
  DB's `tenant_schema_versions` table.

  Runs on application boot and can be invoked manually for new tenants.
  """

  require Logger

  alias PkiPlatformEngine.PlatformRepo

  @migrations_dir "priv/tenant_migrations"

  @doc "Run all pending migrations for all active tenants."
  def migrate_all do
    ensure_tracking_table()

    case list_active_tenants() do
      {:ok, tenants} ->
        results = Enum.map(tenants, &migrate_tenant/1)
        {applied, skipped, failed} = summarize(results)
        Logger.info("tenant_migrator: #{applied} applied, #{skipped} skipped, #{failed} failed across #{length(tenants)} tenant(s)")
        :ok

      {:error, reason} ->
        Logger.error("tenant_migrator: failed to list tenants: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc "Run all pending migrations for a single tenant."
  def migrate_tenant(%{id: tenant_id, database_name: db_name}) do
    migrate_tenant(tenant_id, db_name)
  end

  def migrate_tenant(tenant_id, db_name) do
    migrations = list_migrations()
    applied = list_applied_versions(tenant_id)

    pending = Enum.reject(migrations, fn {version, _path, _desc} -> version in applied end)

    if pending == [] do
      Logger.debug("tenant_migrator: #{tenant_id} — all #{length(migrations)} migrations applied")
      {:ok, :up_to_date}
    else
      Logger.info("tenant_migrator: #{tenant_id} — applying #{length(pending)} pending migration(s)")

      Enum.reduce_while(pending, {:ok, 0}, fn {version, path, desc}, {:ok, count} ->
        case apply_migration(tenant_id, db_name, version, path, desc) do
          :ok -> {:cont, {:ok, count + 1}}
          {:error, reason} -> {:halt, {:error, version, reason}}
        end
      end)
    end
  rescue
    e ->
      Logger.error("tenant_migrator: #{tenant_id} crashed: #{Exception.message(e)}")
      {:error, :crash, Exception.message(e)}
  end

  # ── Private ──────────────────────────────────────────────────────────

  defp list_migrations do
    dir = Application.app_dir(:pki_platform_engine, @migrations_dir)

    case File.ls(dir) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".sql"))
        |> Enum.sort()
        |> Enum.map(fn filename ->
          version = filename |> String.split("_", parts: 2) |> List.first()
          desc = filename |> String.trim_trailing(".sql")
          {version, Path.join(dir, filename), desc}
        end)

      {:error, _} ->
        Logger.warning("tenant_migrator: migrations directory not found: #{dir}")
        []
    end
  end

  defp list_applied_versions(tenant_id) do
    try do
      PlatformRepo.query!(
        "SELECT version FROM tenant_schema_versions WHERE tenant_id = $1",
        [Ecto.UUID.dump!(tenant_id)]
      ).rows
      |> Enum.map(fn [v] -> v end)
    rescue
      _ -> []
    end
  end

  defp apply_migration(tenant_id, db_name, version, sql_path, desc) do
    sql = File.read!(sql_path)

    config = Application.get_env(:pki_platform_engine, PkiPlatformEngine.TenantRepo, [])
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
          # Split multi-statement SQL and execute each individually, wrapped in a transaction
          statements =
            sql
            |> String.split(~r/;\s*\n/)
            |> Enum.map(fn stmt ->
              stmt
              |> String.split("\n")
              |> Enum.reject(&String.match?(&1, ~r/^\s*--/))
              |> Enum.join("\n")
              |> String.trim()
            end)
            |> Enum.reject(&(&1 == ""))

          # Begin transaction for atomicity
          Postgrex.query!(conn, "BEGIN", [])

          result =
            Enum.reduce_while(statements, :ok, fn stmt, :ok ->
              case Postgrex.query(conn, stmt, []) do
                {:ok, _} -> {:cont, :ok}
                {:error, err} -> {:halt, {:error, err}}
              end
            end)

          case result do
            :ok ->
              Postgrex.query!(conn, "COMMIT", [])
              record_applied(tenant_id, version, desc)
              Logger.info("tenant_migrator: #{tenant_id} applied #{version} (#{desc})")
              :ok

            {:error, err} ->
              Postgrex.query(conn, "ROLLBACK", [])
              Logger.error("tenant_migrator: #{tenant_id} failed #{version}: #{inspect(err)}")
              {:error, err}
          end
        after
          GenServer.stop(conn)
        end

      {:error, reason} ->
        Logger.error("tenant_migrator: cannot connect to #{db_name}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp record_applied(tenant_id, version, desc) do
    PlatformRepo.query!(
      """
      INSERT INTO tenant_schema_versions (tenant_id, version, description, applied_at)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (tenant_id, version) DO NOTHING
      """,
      [Ecto.UUID.dump!(tenant_id), version, desc, DateTime.utc_now()]
    )
  end

  defp ensure_tracking_table do
    # The table is created by platform Ecto migration.
    # This is a safety check — if it doesn't exist, migrations will skip gracefully.
    try do
      PlatformRepo.query!("SELECT 1 FROM tenant_schema_versions LIMIT 0")
      :ok
    rescue
      _ ->
        Logger.warning("tenant_migrator: tenant_schema_versions table not found. Run platform migrations first.")
        :error
    end
  end

  defp list_active_tenants do
    try do
      # Migrate ALL tenants (including suspended) so schemas are ready on reactivation
      rows = PlatformRepo.query!(
        "SELECT id, database_name FROM tenants WHERE status IN ('active', 'suspended')",
        []
      ).rows

      tenants = Enum.map(rows, fn [id, db_name] ->
        # Postgrex returns UUID as 16-byte binary; cast to string for downstream use
        string_id = case Ecto.UUID.cast(id) do
          {:ok, sid} -> sid
          _ -> id
        end
        %{id: string_id, database_name: db_name}
      end)
      {:ok, tenants}
    rescue
      e ->
        {:error, Exception.message(e)}
    end
  end

  defp summarize(results) do
    Enum.reduce(results, {0, 0, 0}, fn
      {:ok, :up_to_date}, {a, s, f} -> {a, s + 1, f}
      {:ok, count}, {a, s, f} when is_integer(count) -> {a + count, s, f}
      {:error, _, _}, {a, s, f} -> {a, s, f + 1}
      _, {a, s, f} -> {a, s, f}
    end)
  end

  defp parse_conn_config(config) do
    hostname = config[:hostname] || "localhost"
    port = config[:port] || 5432
    username = config[:username] || "postgres"
    password = config[:password] || "postgres"
    {hostname, port, username, password}
  end
end
