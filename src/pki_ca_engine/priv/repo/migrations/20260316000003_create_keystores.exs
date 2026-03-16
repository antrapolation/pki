defmodule PkiCaEngine.Repo.Migrations.CreateKeystores do
  use Ecto.Migration

  def change do
    create table(:keystores) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :type, :string, null: false
      add :config, :binary
      add :status, :string, default: "active", null: false
      add :provider_name, :string

      timestamps()
    end

    create index(:keystores, [:ca_instance_id])
  end
end
