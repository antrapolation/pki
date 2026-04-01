defmodule PkiPlatformEngine.PlatformRepo.Migrations.AddMustChangePasswordToPlatformAdmins do
  use Ecto.Migration

  def change do
    alter table(:platform_admins) do
      add :must_change_password, :boolean, default: false
      add :credential_expires_at, :utc_datetime
    end
  end
end
