defmodule PkiPlatformEngine.PlatformRepo.Migrations.AddSchemaModeToTenants do
  use Ecto.Migration

  def change do
    alter table(:tenants) do
      # Existing tenants keep "database" mode; new tenants default to "schema"
      add :schema_mode, :string, null: false, default: "database"
    end
  end
end
