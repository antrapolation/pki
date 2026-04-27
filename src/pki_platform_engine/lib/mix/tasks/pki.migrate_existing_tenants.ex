defmodule Mix.Tasks.Pki.MigrateExistingTenants do
  use Mix.Task
  require Logger

  @shortdoc "Idempotent: add audit schema to existing schema-mode tenants"

  @moduledoc """
  Run after deploying the per-tenant audit schema changes to a VPS
  with existing schema-mode tenants. Safe to run multiple times — all SQL
  uses CREATE IF NOT EXISTS.

  Usage:
    mix pki.migrate_existing_tenants
  """

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    import Ecto.Query
    alias PkiPlatformEngine.{PlatformRepo, Tenant, TenantPrefix, Provisioner}

    tenants =
      PlatformRepo.all(from t in Tenant, where: t.schema_mode == "schema", order_by: t.inserted_at)

    IO.puts("Found #{length(tenants)} schema-mode tenant(s).")

    for tenant <- tenants do
      IO.write("  #{tenant.slug} (#{tenant.id}) ... ")
      prefixes = TenantPrefix.all_prefixes(tenant.id)

      errors =
        [
          fn -> Provisioner.ensure_schema_exists(prefixes.audit_prefix) end,
          fn -> Provisioner.apply_tenant_schema_file("tenant_audit_schema.sql", "audit", prefixes.audit_prefix) end
        ]
        |> Enum.flat_map(fn f ->
          try do
            case f.() do
              :ok -> []
              {:error, reason} -> [inspect(reason)]
            end
          rescue
            e -> [Exception.message(e)]
          end
        end)

      if errors == [] do
        IO.puts("OK")
      else
        IO.puts("FAILED")
        Enum.each(errors, &IO.puts("    #{&1}"))
      end
    end

    IO.puts("Done.")
  end
end
