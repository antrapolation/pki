defmodule PkiValidation.Repo.Migrations.CreateCrlMetadata do
  use Ecto.Migration

  def change do
    create table(:crl_metadata, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false
      add :issuer_key_id, :binary_id, null: false
      add :crl_number, :bigint, null: false, default: 1
      add :last_generated_at, :utc_datetime_usec
      add :last_der_bytes, :binary
      add :last_der_size, :integer, default: 0
      add :generation_count, :integer, null: false, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:crl_metadata, [:issuer_key_id])
  end
end
