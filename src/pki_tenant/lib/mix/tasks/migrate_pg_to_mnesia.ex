defmodule Mix.Tasks.Pki.MigrateTenantData do
  @moduledoc """
  One-time migration of tenant data from PostgreSQL (schema-mode) to Mnesia.

  Reads CA instances, issuer keys, key ceremonies, threshold shares,
  issued certificates, cert profiles, RA instances, RA-CA connections,
  API keys, and CSR requests from a tenant's PostgreSQL schema and inserts
  them as PkiMnesia structs.

  Usage:
    mix pki.migrate_tenant_data --tenant-slug comp-4 --pg-url postgres://user:pass@host/pki_platform
    mix pki.migrate_tenant_data --tenant-slug comp-5 --pg-url postgres://... --mnesia-dir /custom/path
  """
  use Mix.Task

  @shortdoc "Migrate tenant data from PostgreSQL to Mnesia"

  @tables [
    {"ca_instances", PkiMnesia.Structs.CaInstance},
    {"issuer_keys", PkiMnesia.Structs.IssuerKey},
    {"key_ceremonies", PkiMnesia.Structs.KeyCeremony},
    {"threshold_shares", PkiMnesia.Structs.ThresholdShare},
    {"issued_certificates", PkiMnesia.Structs.IssuedCertificate},
    {"cert_profiles", PkiMnesia.Structs.CertProfile},
    {"ra_instances", PkiMnesia.Structs.RaInstance},
    {"ra_ca_connections", PkiMnesia.Structs.RaCaConnection},
    {"api_keys", PkiMnesia.Structs.ApiKey},
    {"csr_requests", PkiMnesia.Structs.CsrRequest}
  ]

  @impl Mix.Task
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, switches: [
      tenant_slug: :string,
      pg_url: :string,
      mnesia_dir: :string
    ])

    slug = opts[:tenant_slug] || raise "Missing --tenant-slug"
    pg_url = opts[:pg_url] || raise "Missing --pg-url"
    mnesia_dir = opts[:mnesia_dir] || "/var/lib/pki/tenants/#{slug}/mnesia"

    Mix.shell().info("Migrating tenant #{slug} from PostgreSQL to Mnesia...")
    Mix.shell().info("  PG URL: #{String.replace(pg_url, ~r/:[^:@]+@/, ":****@")}")
    Mix.shell().info("  Mnesia dir: #{mnesia_dir}")

    # Ensure required apps are started
    Application.ensure_all_started(:postgrex)

    # 1. Start Mnesia
    setup_mnesia(mnesia_dir)

    # 2. Connect to PostgreSQL
    {:ok, conn} = Postgrex.start_link(url: pg_url)
    schema = "tenant_#{String.replace(slug, "-", "_")}"

    # 3. Verify the PG schema exists
    verify_schema_exists(conn, schema)

    # 4. Migrate each table
    Enum.each(@tables, fn {pg_table, struct_mod} ->
      migrate_table(conn, schema, pg_table, struct_mod)
    end)

    Mix.shell().info("\nMigration complete for tenant #{slug}")

    # 5. Verify counts
    verify_counts(conn, schema)

    # 6. Cleanup
    GenServer.stop(conn)
    :mnesia.stop()

    Mix.shell().info("\nDone. Mnesia data written to #{mnesia_dir}")
  end

  defp setup_mnesia(mnesia_dir) do
    File.mkdir_p!(mnesia_dir)

    # Stop Mnesia if already running
    :mnesia.stop()

    Application.put_env(:mnesia, :dir, String.to_charlist(mnesia_dir))
    :mnesia.create_schema([node()])
    :ok = :mnesia.start()
    :ok = PkiMnesia.Schema.create_tables()

    table_names = :mnesia.system_info(:local_tables) -- [:schema]
    :mnesia.wait_for_tables(table_names, 10_000)
  end

  defp verify_schema_exists(conn, schema) do
    {:ok, %{rows: rows}} = Postgrex.query(
      conn,
      "SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1",
      [schema]
    )

    if rows == [] do
      raise "PostgreSQL schema '#{schema}' not found. Available schemas: check with \\dn"
    end

    Mix.shell().info("  Found PG schema: #{schema}")
  end

  defp migrate_table(conn, schema, pg_table, struct_mod) do
    case Postgrex.query(conn, "SELECT * FROM #{schema}.#{pg_table}", []) do
      {:ok, result} ->
        migrated = Enum.reduce(result.rows, 0, fn row, count ->
          attrs = build_attrs(result.columns, row, pg_table)

          struct = struct_mod.new(attrs)
          case PkiMnesia.Repo.insert(struct) do
            {:ok, _} -> count + 1
            {:error, reason} ->
              Mix.shell().error("    WARN: Failed to insert #{pg_table} row: #{inspect(reason)}")
              count
          end
        end)

        Mix.shell().info("  Migrated #{migrated}/#{result.num_rows} #{pg_table}")

      {:error, %{postgres: %{code: :undefined_table}}} ->
        Mix.shell().info("  Skipped #{pg_table} (table does not exist in PG schema)")

      {:error, reason} ->
        Mix.shell().error("  ERROR migrating #{pg_table}: #{inspect(reason)}")
    end
  end

  defp build_attrs(columns, row, pg_table) do
    base_attrs =
      columns
      |> Enum.zip(row)
      |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)

    # Handle schema differences between PG and Mnesia structs
    case pg_table do
      "threshold_shares" ->
        # PG may have custodian_user_id instead of custodian_name
        if Map.has_key?(base_attrs, :custodian_name) do
          base_attrs
        else
          Map.put(base_attrs, :custodian_name,
            base_attrs[:custodian_user_id] || "migrated-#{base_attrs[:id]}")
        end

      _ ->
        base_attrs
    end
  end

  defp verify_counts(conn, schema) do
    Mix.shell().info("\n  Verification:")

    Enum.each(@tables, fn {pg_table, struct_mod} ->
      pg_count = case Postgrex.query(conn, "SELECT COUNT(*) FROM #{schema}.#{pg_table}", []) do
        {:ok, %{rows: [[count]]}} -> count
        _ -> "N/A"
      end

      mnesia_count = case PkiMnesia.Repo.all(struct_mod) do
        {:ok, records} -> length(records)
        _ -> "ERR"
      end

      status = cond do
        pg_count == "N/A" -> "SKIP"
        pg_count == mnesia_count -> "OK"
        true -> "MISMATCH"
      end

      Mix.shell().info("    #{pg_table}: PG=#{pg_count} Mnesia=#{mnesia_count} [#{status}]")
    end)
  end
end
