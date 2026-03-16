defmodule PkiCaEngine.Repo.Migrations.CreateCaUsers do
  use Ecto.Migration

  def change do
    create table(:ca_users) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :did, :string, null: false
      add :display_name, :string
      add :role, :string, null: false
      add :status, :string, default: "active", null: false

      timestamps()
    end

    create unique_index(:ca_users, [:ca_instance_id, :did])
    create index(:ca_users, [:ca_instance_id])
  end
end
