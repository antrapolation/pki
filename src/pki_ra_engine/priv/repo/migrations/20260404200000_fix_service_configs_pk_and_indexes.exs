defmodule PkiRaEngine.Repo.Migrations.FixServiceConfigsPkAndIndexes do
  use Ecto.Migration

  @moduledoc """
  Fixes:
  1. service_configs PK mismatch — schema expects binary_id but migration created integer PK
  2. DCV unique index too restrictive — prevents retry after expiry (use partial index)
  3. Missing performance indexes on csr_requests.status and dcv_challenges.status/expires_at
  """

  def up do
    # 1. Fix service_configs PK: drop old integer PK, add binary_id PK
    #    Only needed if the table still has an integer PK column
    execute """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
        AND table_name = 'service_configs' AND column_name = 'id'
        AND data_type = 'integer'
      ) THEN
        -- Drop the old integer PK and recreate as UUID
        ALTER TABLE service_configs DROP CONSTRAINT service_configs_pkey;
        ALTER TABLE service_configs DROP COLUMN id;
        ALTER TABLE service_configs ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid();
        ALTER TABLE service_configs ADD PRIMARY KEY (id);
      END IF;
    END $$;
    """

    # 2. Replace DCV unique index with partial index (only pending challenges must be unique)
    drop_if_exists unique_index(:dcv_challenges, [:csr_id, :domain, :method])

    create unique_index(:dcv_challenges, [:csr_id, :domain, :method],
      where: "status = 'pending'",
      name: :dcv_challenges_active_unique_index
    )

    # 3. Add missing performance indexes
    create_if_not_exists index(:csr_requests, [:status])
    create_if_not_exists index(:dcv_challenges, [:status])
    create_if_not_exists index(:dcv_challenges, [:expires_at])
  end

  def down do
    # service_configs PK change is irreversible — restore from backup if rollback required
    raise "This migration is irreversible (service_configs PK changed from integer to UUID). Restore from backup if rollback is needed."
  end
end
