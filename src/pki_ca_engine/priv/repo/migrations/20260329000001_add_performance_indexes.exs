defmodule PkiCaEngine.Repo.Migrations.AddPerformanceIndexes do
  use Ecto.Migration

  def change do
    # ca_users: fast lookup by status and role (used in user listing and ACL checks)
    create_if_not_exists index(:ca_users, [:status])
    create_if_not_exists index(:ca_users, [:role])
    create_if_not_exists index(:ca_users, [:username])

    # issuer_keys: fast lookup by status (active keys are fetched frequently)
    create_if_not_exists index(:issuer_keys, [:status])
    create_if_not_exists index(:issuer_keys, [:ca_instance_id, :status])

    # issued_certificates: status lookups for revocation checks and CRL generation
    create_if_not_exists index(:issued_certificates, [:status])
    create_if_not_exists index(:issued_certificates, [:issuer_key_id, :status])
    create_if_not_exists index(:issued_certificates, [:not_after])
  end
end
