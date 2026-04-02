defmodule PkiCaEngine.Repo.Migrations.DropCaUsersFkFromCeremoniesAndShares do
  @moduledoc """
  Drop foreign key constraints that reference ca_users from key_ceremonies
  and threshold_shares. Users now live in the platform DB, so these FKs
  cannot be enforced at the database level. Application-level validation
  ensures valid platform user IDs are used.
  """
  use Ecto.Migration

  def change do
    # key_ceremonies.initiated_by — was FK to ca_users
    drop constraint(:key_ceremonies, "key_ceremonies_initiated_by_fkey")

    # threshold_shares.custodian_user_id — was FK to ca_users, NOT NULL
    drop constraint(:threshold_shares, "threshold_shares_custodian_user_id_fkey")
  end
end
