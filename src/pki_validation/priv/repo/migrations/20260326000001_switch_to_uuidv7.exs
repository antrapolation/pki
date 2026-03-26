defmodule PkiValidation.Repo.Migrations.SwitchToUuidv7 do
  use Ecto.Migration

  def change do
    drop table(:certificate_status)

    create table(:certificate_status, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :serial_number, :string, null: false
      add :issuer_key_id, :binary_id, null: false
      add :subject_dn, :string, null: false
      add :status, :string, null: false, default: "active"
      add :not_before, :utc_datetime_usec, null: false
      add :not_after, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
      add :revocation_reason, :string

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:certificate_status, [:serial_number])
    create index(:certificate_status, [:status])
    create index(:certificate_status, [:issuer_key_id])
  end
end
