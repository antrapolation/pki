defmodule PkiAuditTrail.Repo.Migrations.CreateAuditEvents do
  use Ecto.Migration

  def change do
    create table(:audit_events) do
      add :event_id, :uuid, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :node_name, :string, null: false
      add :actor_did, :string, null: false
      add :actor_role, :string, null: false
      add :action, :string, null: false
      add :resource_type, :string, null: false
      add :resource_id, :string, null: false
      add :details, :map, default: %{}
      add :prev_hash, :string, null: false, size: 64
      add :event_hash, :string, null: false, size: 64
    end

    create unique_index(:audit_events, [:event_id])
    create index(:audit_events, [:action])
    create index(:audit_events, [:actor_did])
    create index(:audit_events, [:resource_type, :resource_id])
    create index(:audit_events, [:timestamp])
  end
end
