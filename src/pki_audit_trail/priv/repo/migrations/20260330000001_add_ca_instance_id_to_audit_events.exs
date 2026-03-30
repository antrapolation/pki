defmodule PkiAuditTrail.Repo.Migrations.AddCaInstanceIdToAuditEvents do
  use Ecto.Migration

  def change do
    alter table(:audit_events) do
      add :ca_instance_id, :string
    end

    create index(:audit_events, [:ca_instance_id])
  end
end
