defmodule PkiCaEngine.Repo.Migrations.CreateIssuerKeys do
  use Ecto.Migration

  def change do
    create table(:issuer_keys) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :key_alias, :string, null: false
      add :algorithm, :string, null: false
      add :status, :string, default: "pending", null: false
      add :keystore_ref, :binary
      add :is_root, :boolean, default: false
      add :threshold_config, :map, default: %{}
      add :certificate_der, :binary
      add :certificate_pem, :text

      timestamps()
    end

    create unique_index(:issuer_keys, [:ca_instance_id, :key_alias])
    create index(:issuer_keys, [:ca_instance_id])
  end
end
