defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreateTenantSchemaVersions do
  use Ecto.Migration

  def change do
    create table(:tenant_schema_versions, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :tenant_id, :binary_id, null: false
      add :version, :string, null: false
      add :description, :string
      add :applied_at, :utc_datetime_usec, null: false
    end

    create unique_index(:tenant_schema_versions, [:tenant_id, :version])
    create index(:tenant_schema_versions, [:tenant_id])
  end
end
