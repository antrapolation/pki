defmodule PkiCaEngine.Repo.Migrations.AddCredentialExpiryToCaUsers do
  use Ecto.Migration

  def change do
    alter table(:ca_users) do
      add :must_change_password, :boolean, default: false
      add :credential_expires_at, :utc_datetime
    end
  end
end
