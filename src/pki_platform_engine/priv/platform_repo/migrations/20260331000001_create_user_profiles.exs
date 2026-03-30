defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreateUserProfiles do
  use Ecto.Migration

  def change do
    create table(:user_profiles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :username, :string, null: false
      add :password_hash, :string, null: false
      add :display_name, :string
      add :email, :string
      add :status, :string, null: false, default: "active"
      add :must_change_password, :boolean, default: false
      add :credential_expires_at, :utc_datetime
      timestamps()
    end

    create unique_index(:user_profiles, [:username])
    create index(:user_profiles, [:email])
    create index(:user_profiles, [:status])

    create table(:user_tenant_roles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_profile_id, references(:user_profiles, type: :binary_id, on_delete: :delete_all), null: false
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :delete_all), null: false
      add :role, :string, null: false
      add :portal, :string, null: false
      add :ca_instance_id, :string
      add :status, :string, null: false, default: "active"
      timestamps()
    end

    create unique_index(:user_tenant_roles, [:user_profile_id, :tenant_id, :portal])
    create index(:user_tenant_roles, [:tenant_id])
    create index(:user_tenant_roles, [:user_profile_id])
  end
end
