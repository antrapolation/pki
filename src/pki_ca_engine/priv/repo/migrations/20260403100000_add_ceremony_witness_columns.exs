defmodule PkiCaEngine.Repo.Migrations.AddCeremonyWitnessColumns do
  use Ecto.Migration

  def change do
    alter table(:key_ceremonies) do
      add :auditor_user_id, :binary_id
      add :time_window_hours, :integer, default: 24
    end

    alter table(:threshold_shares) do
      add :key_label, :string
      add :status, :string, default: "pending"
      add :accepted_at, :utc_datetime
    end

    create table(:ceremony_attestations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ceremony_id, references(:key_ceremonies, type: :binary_id, on_delete: :delete_all), null: false
      add :auditor_user_id, :binary_id, null: false
      add :phase, :string, null: false
      add :attested_at, :utc_datetime, null: false
      add :details, :map, default: %{}

      timestamps()
    end

    create index(:ceremony_attestations, [:ceremony_id])
    create unique_index(:ceremony_attestations, [:ceremony_id, :phase])
  end
end
