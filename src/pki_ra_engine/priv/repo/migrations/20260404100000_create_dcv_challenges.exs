defmodule PkiRaEngine.Repo.Migrations.CreateDcvChallenges do
  use Ecto.Migration

  def change do
    create table(:dcv_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :csr_id, references(:csr_requests, type: :binary_id, on_delete: :delete_all), null: false
      add :domain, :string, null: false
      add :method, :string, null: false
      add :token, :string, null: false
      add :token_value, :string, null: false
      add :status, :string, default: "pending", null: false
      add :initiated_by, :binary_id
      add :verified_at, :utc_datetime
      add :expires_at, :utc_datetime, null: false
      add :attempts, :integer, default: 0
      add :last_checked_at, :utc_datetime
      add :error_details, :string

      timestamps()
    end

    create index(:dcv_challenges, [:csr_id])
    create unique_index(:dcv_challenges, [:csr_id, :domain, :method])
  end
end
