defmodule PkiCaEngine.Repo.Migrations.AddPerformanceIndexes do
  use Ecto.Migration

  def change do
    # ca_users: fast lookup by status and role (used in user listing and ACL checks)
    create index(:ca_users, [:status])
    create index(:ca_users, [:role])
    create index(:ca_users, [:username])

    # issuer_keys: fast lookup by status (active keys are fetched frequently)
    create index(:issuer_keys, [:status])
    create index(:issuer_keys, [:ca_instance_id, :status])

    # issued_certificates: status lookups for revocation checks and CRL generation
    create index(:issued_certificates, [:status])
    create index(:issued_certificates, [:issuer_key_id, :status])
    create index(:issued_certificates, [:not_after])
  end
end
