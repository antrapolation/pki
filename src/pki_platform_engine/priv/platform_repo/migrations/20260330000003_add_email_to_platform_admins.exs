defmodule PkiPlatformEngine.PlatformRepo.Migrations.AddEmailToPlatformAdmins do
  use Ecto.Migration

  def change do
    alter table(:platform_admins) do
      add :email, :string
    end
  end
end
