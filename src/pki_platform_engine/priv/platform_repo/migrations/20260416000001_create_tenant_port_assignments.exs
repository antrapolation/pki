defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreateTenantPortAssignments do
  use Ecto.Migration

  def change do
    create table(:tenant_port_assignments, primary_key: false) do
      add :tenant_id, :uuid, primary_key: true
      add :port, :integer, null: false
      add :assigned_at, :utc_datetime, default: fragment("NOW()")
    end

    create unique_index(:tenant_port_assignments, [:port])
  end
end
