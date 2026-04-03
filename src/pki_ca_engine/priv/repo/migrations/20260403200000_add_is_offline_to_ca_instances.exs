defmodule PkiCaEngine.Repo.Migrations.AddIsOfflineToCaInstances do
  use Ecto.Migration

  def change do
    alter table(:ca_instances) do
      add :is_offline, :boolean, default: false
    end
  end
end
