defmodule PkiRaEngine.Repo.Migrations.AddTenantIdToRaUsers do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :tenant_id, :uuid
    end

    create index(:ra_users, [:tenant_id])
    create unique_index(:ra_users, [:username, :tenant_id])
  end
end
