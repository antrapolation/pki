defmodule PkiRaEngine.Repo.Migrations.AddPerformanceIndexes do
  use Ecto.Migration

  def change do
    # ra_users: fast lookup by status and role (used in user listing and auth)
    create_if_not_exists index(:ra_users, [:status])
    create_if_not_exists index(:ra_users, [:role])
    create_if_not_exists index(:ra_users, [:username])

    # csr_requests: reviewed_at for audit queries; submitted_at for time-range scans
    create_if_not_exists index(:csr_requests, [:submitted_at])
    create_if_not_exists index(:csr_requests, [:reviewed_at])
  end
end
