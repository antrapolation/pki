defmodule PkiCaEngine.Repo.Migrations.CreateKeypairAccess do
  use Ecto.Migration

  def change do
    create table(:keypair_access) do
      add :issuer_key_id, references(:issuer_keys, on_delete: :delete_all), null: false
      add :user_id, references(:ca_users, on_delete: :delete_all), null: false
      add :granted_by, references(:ca_users, on_delete: :nilify_all)
      add :granted_at, :utc_datetime, null: false
    end

    create unique_index(:keypair_access, [:issuer_key_id, :user_id])
    create index(:keypair_access, [:user_id])
  end
end
