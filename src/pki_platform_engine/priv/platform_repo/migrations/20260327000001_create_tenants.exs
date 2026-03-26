defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreateTenants do
  use Ecto.Migration

  def change do
    create table(:tenants, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :string, null: false
      add :slug, :string, null: false
      add :database_name, :string, null: false
      add :status, :string, null: false, default: "initialized"
      add :signing_algorithm, :string, null: false, default: "ECC-P256"
      add :kem_algorithm, :string, null: false, default: "ECDH-P256"
      add :metadata, :map, default: %{}
      timestamps()
    end

    create unique_index(:tenants, [:slug])
    create unique_index(:tenants, [:name])
    create unique_index(:tenants, [:database_name])
  end
end
