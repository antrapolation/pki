defmodule PkiCaEngine.Repo.Migrations.CreateKeyCeremonies do
  use Ecto.Migration

  def change do
    create table(:key_ceremonies) do
      add :ca_instance_id, references(:ca_instances, on_delete: :delete_all), null: false
      add :issuer_key_id, references(:issuer_keys, on_delete: :delete_all)
      add :ceremony_type, :string, null: false
      add :status, :string, default: "initiated", null: false
      add :initiated_by, references(:ca_users, on_delete: :nilify_all)
      add :participants, :map, default: %{}
      add :algorithm, :string
      add :keystore_id, references(:keystores, on_delete: :nilify_all)
      add :threshold_k, :integer
      add :threshold_n, :integer
      add :domain_info, :map, default: %{}
      add :window_expires_at, :utc_datetime

      timestamps()
    end

    create index(:key_ceremonies, [:ca_instance_id])
    create index(:key_ceremonies, [:issuer_key_id])
  end
end
