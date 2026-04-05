defmodule PkiRaEngine.Repo.Migrations.AddStatusToCertProfiles do
  use Ecto.Migration

  def change do
    alter table(:cert_profiles) do
      add :status, :string, default: "active", null: false
    end

    create index(:cert_profiles, [:status])
  end
end
