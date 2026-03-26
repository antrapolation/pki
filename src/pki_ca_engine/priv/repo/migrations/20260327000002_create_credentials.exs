defmodule PkiCaEngine.Repo.Migrations.CreateCredentials do
  use Ecto.Migration

  def change do
    create table(:credentials, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :credential_type, :string, null: false
      add :algorithm, :string, null: false
      add :public_key, :binary, null: false
      add :encrypted_private_key, :binary, null: false
      add :salt, :binary, null: false
      add :certificate, :binary
      add :status, :string, null: false, default: "active"
      add :user_id, references(:ca_users, type: :uuid, on_delete: :delete_all), null: false

      timestamps()
    end

    create index(:credentials, [:user_id])
    create index(:credentials, [:user_id, :credential_type])
  end
end
