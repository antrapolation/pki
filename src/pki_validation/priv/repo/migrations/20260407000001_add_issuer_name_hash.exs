defmodule PkiValidation.Repo.Migrations.AddIssuerNameHash do
  use Ecto.Migration

  def change do
    alter table(:certificate_status) do
      add :issuer_name_hash, :binary
    end

    create index(:certificate_status, [:issuer_key_id, :serial_number])
    create index(:certificate_status, [:status, :revoked_at])
  end
end
