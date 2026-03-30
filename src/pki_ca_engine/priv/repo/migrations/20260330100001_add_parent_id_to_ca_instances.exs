defmodule PkiCaEngine.Repo.Migrations.AddParentIdToCaInstances do
  use Ecto.Migration

  def change do
    alter table(:ca_instances) do
      add :parent_id, references(:ca_instances, type: :binary_id, on_delete: :restrict)
    end

    create index(:ca_instances, [:parent_id])
  end
end
