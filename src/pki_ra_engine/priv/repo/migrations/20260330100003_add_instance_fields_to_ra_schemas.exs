defmodule PkiRaEngine.Repo.Migrations.AddInstanceFieldsToRaSchemas do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :nilify_all)
    end

    alter table(:ra_api_keys) do
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :nilify_all)
    end

    alter table(:cert_profiles) do
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :nilify_all)
      add :issuer_key_id, :string
    end

    create index(:ra_users, [:ra_instance_id])
    create index(:ra_api_keys, [:ra_instance_id])
    create index(:cert_profiles, [:ra_instance_id])
    create index(:cert_profiles, [:issuer_key_id])
  end
end
