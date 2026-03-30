defmodule PkiRaEngine.Repo.Migrations.CreateRaInstances do
  use Ecto.Migration

  def change do
    create table(:ra_instances, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :status, :string, null: false, default: "initialized"
      add :created_by, :string

      timestamps()
    end

    create unique_index(:ra_instances, [:name])
  end
end
