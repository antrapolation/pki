defmodule PkiCaEngine.Repo.Migrations.CreateKeyVaultTables do
  use Ecto.Migration

  def change do
    create table(:managed_keypairs, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :string, null: false
      add :algorithm, :string, null: false
      add :protection_mode, :string, null: false
      add :public_key, :binary
      add :encrypted_private_key, :binary
      add :encrypted_password, :binary
      add :threshold_k, :integer
      add :threshold_n, :integer
      add :status, :string, null: false, default: "pending"
      add :metadata, :map, default: %{}
      add :ca_instance_id, references(:ca_instances, type: :uuid, on_delete: :delete_all), null: false
      timestamps()
    end

    create unique_index(:managed_keypairs, [:ca_instance_id, :name])
    create index(:managed_keypairs, [:ca_instance_id])
    create index(:managed_keypairs, [:status])

    create table(:keypair_grants, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :signed_envelope, :binary, null: false
      add :granted_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
      add :managed_keypair_id, references(:managed_keypairs, type: :uuid, on_delete: :delete_all), null: false
      add :credential_id, references(:credentials, type: :uuid, on_delete: :delete_all), null: false
      timestamps()
    end

    create unique_index(:keypair_grants, [:managed_keypair_id, :credential_id])
    create index(:keypair_grants, [:credential_id])
  end
end
