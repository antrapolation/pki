defmodule PkiRaEngine.Repo.Migrations.SwitchToUuidv7 do
  use Ecto.Migration

  def change do
    # Drop tables in dependency order (children first)
    drop_if_exists table(:ra_api_keys)
    drop_if_exists table(:csr_requests)
    drop_if_exists table(:service_configs)
    drop_if_exists table(:cert_profiles)
    drop_if_exists table(:ra_users)

    # Recreate ra_users with UUID PK, no did field
    create table(:ra_users, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :username, :string
      add :password_hash, :string
      add :display_name, :string
      add :role, :string, null: false
      add :status, :string, null: false, default: "active"

      timestamps()
    end

    create unique_index(:ra_users, [:username])

    # Recreate cert_profiles with UUID PK
    create table(:cert_profiles, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :string, null: false
      add :subject_dn_policy, :map, default: %{}
      add :issuer_policy, :map, default: %{}
      add :key_usage, :string
      add :ext_key_usage, :string
      add :digest_algo, :string
      add :validity_policy, :map, default: %{}
      add :timestamping_policy, :map, default: %{}
      add :crl_policy, :map, default: %{}
      add :ocsp_policy, :map, default: %{}
      add :ca_repository_url, :string
      add :issuer_url, :string
      add :included_extensions, :map, default: %{}
      add :renewal_policy, :map, default: %{}
      add :notification_profile, :map, default: %{}
      add :cert_publish_policy, :map, default: %{}

      timestamps()
    end

    create unique_index(:cert_profiles, [:name])

    # Recreate csr_requests with UUID PK and UUID FKs
    create table(:csr_requests, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :csr_der, :binary
      add :csr_pem, :text
      add :subject_dn, :string, null: false
      add :cert_profile_id, references(:cert_profiles, type: :uuid, on_delete: :restrict),
        null: false
      add :status, :string, null: false, default: "pending"
      add :submitted_at, :utc_datetime_usec, null: false
      add :reviewed_by, references(:ra_users, type: :uuid, on_delete: :nilify_all)
      add :reviewed_at, :utc_datetime_usec
      add :rejection_reason, :text
      add :issued_cert_serial, :string

      timestamps()
    end

    create index(:csr_requests, [:status])
    create index(:csr_requests, [:cert_profile_id])

    # Recreate service_configs with UUID PK
    create table(:service_configs, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :service_type, :string, null: false
      add :port, :integer
      add :url, :string
      add :rate_limit, :integer
      add :ip_whitelist, :map, default: %{}
      add :ip_blacklist, :map, default: %{}
      add :connection_security, :string
      add :credentials, :binary
      add :ca_engine_ref, :string

      timestamps()
    end

    create unique_index(:service_configs, [:service_type])

    # Recreate ra_api_keys with UUID PK and UUID FK
    create table(:ra_api_keys, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :hashed_key, :string, null: false
      add :ra_user_id, references(:ra_users, type: :uuid, on_delete: :delete_all), null: false
      add :label, :string
      add :expiry, :utc_datetime_usec
      add :rate_limit, :integer
      add :status, :string, null: false, default: "active"
      add :revoked_at, :utc_datetime_usec

      timestamps()
    end
  end
end
