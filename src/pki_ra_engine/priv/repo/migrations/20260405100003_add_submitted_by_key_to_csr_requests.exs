defmodule PkiRaEngine.Repo.Migrations.AddSubmittedByKeyToCsrRequests do
  use Ecto.Migration

  def change do
    alter table(:csr_requests) do
      add :submitted_by_key_id, :binary_id
    end

    create index(:csr_requests, [:submitted_by_key_id])
  end
end
