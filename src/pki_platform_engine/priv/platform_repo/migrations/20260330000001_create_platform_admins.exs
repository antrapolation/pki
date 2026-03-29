defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreatePlatformAdmins do
  use Ecto.Migration

  def change do
    create table(:platform_admins, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :username, :string, null: false
      add :password_hash, :string, null: false
      add :display_name, :string, null: false
      add :role, :string, null: false, default: "super_admin"
      add :status, :string, null: false, default: "active"

      timestamps()
    end

    create unique_index(:platform_admins, [:username])
  end
end
