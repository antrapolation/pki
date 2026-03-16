defmodule PkiCaEngine.Repo.Migrations.CreateThresholdShares do
  use Ecto.Migration

  def change do
    create table(:threshold_shares) do
      add :issuer_key_id, references(:issuer_keys, on_delete: :delete_all), null: false
      add :custodian_user_id, references(:ca_users, on_delete: :delete_all), null: false
      add :share_index, :integer, null: false
      add :encrypted_share, :binary, null: false
      add :min_shares, :integer, null: false
      add :total_shares, :integer, null: false

      timestamps()
    end

    create unique_index(:threshold_shares, [:issuer_key_id, :custodian_user_id])
    create index(:threshold_shares, [:issuer_key_id])
  end
end
