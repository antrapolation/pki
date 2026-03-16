defmodule PkiCaEngine.Repo.Migrations.CreateCaInstances do
  use Ecto.Migration

  def change do
    create table(:ca_instances) do
      add :name, :string, null: false
      add :status, :string, default: "initialized", null: false
      add :domain_info, :map, default: %{}
      add :created_by, :string

      timestamps()
    end

    create unique_index(:ca_instances, [:name])
  end
end
