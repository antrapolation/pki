defmodule PkiRaEngine.Repo.Migrations.CreateCsrRequests do
  use Ecto.Migration

  def change do
    create table(:csr_requests) do
      add :csr_der, :binary
      add :csr_pem, :text
      add :subject_dn, :string, null: false
      add :cert_profile_id, references(:cert_profiles, on_delete: :restrict), null: false
      add :status, :string, null: false, default: "pending"
      add :submitted_at, :utc_datetime_usec, null: false
      add :reviewed_by, references(:ra_users, on_delete: :nilify_all)
      add :reviewed_at, :utc_datetime_usec
      add :rejection_reason, :text
      add :issued_cert_serial, :string

      timestamps()
    end

    create index(:csr_requests, [:status])
    create index(:csr_requests, [:cert_profile_id])
  end
end
