defmodule PkiPlatformEngine.MigrationRepo do
  @moduledoc """
  Temporary Ecto Repo used exclusively by the Provisioner to run tenant
  schema migrations. This repo is NOT started as part of the supervision tree
  — it is started and stopped on-demand for each provisioning operation.

  This exists because PlatformRepo may use Ecto.Adapters.SQL.Sandbox in test,
  which is incompatible with Ecto.Migrator. MigrationRepo uses a plain
  DBConnection pool so migrations can run transactionally outside the sandbox.
  """
  use Ecto.Repo,
    otp_app: :pki_platform_engine,
    adapter: Ecto.Adapters.Postgres
end
