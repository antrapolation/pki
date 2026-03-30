defmodule PkiPlatformEngine.PlatformRepo.Migrations.AddEmailToTenants do
  use Ecto.Migration

  def change do
    alter table(:tenants) do
      add :email, :string
    end
  end
end
