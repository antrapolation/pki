defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreatePlatformAuditEvents do
  use Ecto.Migration

  def change do
    create table(:platform_audit_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :timestamp, :utc_datetime_usec, null: false
      add :actor_id, :binary_id
      add :actor_username, :string
      add :action, :string, null: false
      add :target_type, :string
      add :target_id, :binary_id
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :nilify_all)
      add :portal, :string
      add :details, :map, default: %{}

      timestamps(updated_at: false)
    end

    create index(:platform_audit_events, [:tenant_id])
    create index(:platform_audit_events, [:action])
    create index(:platform_audit_events, [:actor_id])
    create index(:platform_audit_events, [:timestamp])
    create index(:platform_audit_events, [:tenant_id, :portal])
  end
end
