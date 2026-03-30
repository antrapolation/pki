defmodule PkiRaEngine.Repo.Migrations.AddCredentialExpiryToRaUsers do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :must_change_password, :boolean, default: false
      add :credential_expires_at, :utc_datetime
    end
  end
end
