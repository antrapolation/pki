defmodule PkiCaEngine.Repo.Migrations.SwitchToUuidv7 do
  use Ecto.Migration

  def change do
    # Drop tables in reverse dependency order (children first)
    drop_if_exists table(:issued_certificates)
    drop_if_exists table(:key_ceremonies)
    drop_if_exists table(:threshold_shares)
    drop_if_exists table(:keypair_access)
    drop_if_exists table(:issuer_keys)
    drop_if_exists table(:keystores)
    drop_if_exists table(:ca_users)
    drop_if_exists table(:ca_instances)

    # Recreate ca_instances with UUID PK
    create table(:ca_instances, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :string, null: false
      add :status, :string, default: "initialized", null: false
      add :domain_info, :map, default: %{}
      add :created_by, :string

      timestamps()
    end

    create unique_index(:ca_instances, [:name])

    # Recreate ca_users with UUID PK, no did field
    create table(:ca_users, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :ca_instance_id, references(:ca_instances, type: :uuid, on_delete: :delete_all), null: false
      add :username, :string
      add :password_hash, :string
      add :display_name, :string
      add :role, :string, null: false
      add :status, :string, default: "active", null: false

      timestamps()
    end

    create unique_index(:ca_users, [:username])
    create index(:ca_users, [:ca_instance_id])

    # Recreate keystores with UUID PK
    create table(:keystores, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :ca_instance_id, references(:ca_instances, type: :uuid, on_delete: :delete_all), null: false
      add :type, :string, null: false
      add :config, :binary
      add :status, :string, default: "active", null: false
      add :provider_name, :string

      timestamps()
    end

    create index(:keystores, [:ca_instance_id])

    # Recreate issuer_keys with UUID PK
    create table(:issuer_keys, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :ca_instance_id, references(:ca_instances, type: :uuid, on_delete: :delete_all), null: false
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

    # Recreate keypair_access with UUID PK and UUID FKs
    create table(:keypair_access, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :issuer_key_id, references(:issuer_keys, type: :uuid, on_delete: :delete_all), null: false
      add :user_id, references(:ca_users, type: :uuid, on_delete: :delete_all), null: false
      add :granted_by, references(:ca_users, type: :uuid, on_delete: :nilify_all)
      add :granted_at, :utc_datetime, null: false
    end

    create unique_index(:keypair_access, [:issuer_key_id, :user_id])
    create index(:keypair_access, [:user_id])

    # Recreate threshold_shares with UUID PK and UUID FKs
    create table(:threshold_shares, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :issuer_key_id, references(:issuer_keys, type: :uuid, on_delete: :delete_all), null: false
      add :custodian_user_id, references(:ca_users, type: :uuid, on_delete: :delete_all), null: false
      add :share_index, :integer, null: false
      add :encrypted_share, :binary, null: false
      add :min_shares, :integer, null: false
      add :total_shares, :integer, null: false

      timestamps()
    end

    create unique_index(:threshold_shares, [:issuer_key_id, :custodian_user_id])
    create index(:threshold_shares, [:issuer_key_id])

    # Recreate key_ceremonies with UUID PK and UUID FKs
    create table(:key_ceremonies, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :ca_instance_id, references(:ca_instances, type: :uuid, on_delete: :delete_all), null: false
      add :issuer_key_id, references(:issuer_keys, type: :uuid, on_delete: :delete_all)
      add :ceremony_type, :string, null: false
      add :status, :string, default: "initiated", null: false
      add :initiated_by, references(:ca_users, type: :uuid, on_delete: :nilify_all)
      add :participants, :map, default: %{}
      add :algorithm, :string
      add :keystore_id, references(:keystores, type: :uuid, on_delete: :nilify_all)
      add :threshold_k, :integer
      add :threshold_n, :integer
      add :domain_info, :map, default: %{}
      add :window_expires_at, :utc_datetime

      timestamps()
    end

    create index(:key_ceremonies, [:ca_instance_id])
    create index(:key_ceremonies, [:issuer_key_id])

    # Recreate issued_certificates with UUID PK and UUID FKs
    create table(:issued_certificates, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :serial_number, :string, null: false
      add :issuer_key_id, references(:issuer_keys, type: :uuid, on_delete: :restrict), null: false
      add :subject_dn, :string, null: false
      add :cert_der, :binary
      add :cert_pem, :text
      add :not_before, :utc_datetime, null: false
      add :not_after, :utc_datetime, null: false
      add :status, :string, default: "active", null: false
      add :revoked_at, :utc_datetime
      add :revocation_reason, :string
      add :cert_profile_id, :string

      timestamps()
    end

    create unique_index(:issued_certificates, [:serial_number])
    create index(:issued_certificates, [:issuer_key_id])
  end
end
