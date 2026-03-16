defmodule PkiCaEngine.Repo.Migrations.CreateIssuedCertificates do
  use Ecto.Migration

  def change do
    create table(:issued_certificates) do
      add :serial_number, :string, null: false
      add :issuer_key_id, references(:issuer_keys, on_delete: :restrict), null: false
      add :subject_dn, :string, null: false
      add :cert_der, :binary
      add :cert_pem, :text
      add :not_before, :utc_datetime, null: false
      add :not_after, :utc_datetime, null: false
      add :status, :string, default: "active", null: false
      add :revoked_at, :utc_datetime
      add :revocation_reason, :string
      add :cert_profile_id, :integer

      timestamps()
    end

    create unique_index(:issued_certificates, [:serial_number])
    create index(:issued_certificates, [:issuer_key_id])
  end
end
