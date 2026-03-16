defmodule PkiRaEngine.Repo.Migrations.CreateRaUsers do
  use Ecto.Migration

  def change do
    create table(:ra_users) do
      add :did, :string, null: false
      add :display_name, :string
      add :role, :string, null: false
      add :status, :string, null: false, default: "active"

      timestamps()
    end

    create unique_index(:ra_users, [:did])
  end
end
