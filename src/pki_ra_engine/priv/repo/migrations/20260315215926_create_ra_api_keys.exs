defmodule PkiRaEngine.Repo.Migrations.CreateRaApiKeys do
  use Ecto.Migration

  def change do
    create table(:ra_api_keys) do
      add :hashed_key, :string, null: false
      add :ra_user_id, references(:ra_users, on_delete: :delete_all), null: false
      add :label, :string
      add :expiry, :utc_datetime_usec
      add :rate_limit, :integer
      add :status, :string, null: false, default: "active"
      add :revoked_at, :utc_datetime_usec

      timestamps()
    end
  end
end
