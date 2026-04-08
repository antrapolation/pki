defmodule PkiValidation.Repo.Migrations.CreateSigningKeyConfig do
  use Ecto.Migration

  def change do
    create table(:signing_key_config, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :issuer_key_id, :binary_id, null: false
      add :algorithm, :string, null: false
      add :certificate_pem, :text, null: false
      add :encrypted_private_key, :binary, null: false
      add :not_before, :utc_datetime_usec, null: false
      add :not_after, :utc_datetime_usec, null: false
      add :status, :string, null: false, default: "active"

      timestamps(type: :utc_datetime_usec)
    end

    create index(:signing_key_config, [:issuer_key_id])

    create unique_index(:signing_key_config, [:issuer_key_id],
             where: "status = 'active'",
             name: :signing_key_config_one_active_per_issuer)
  end
end
