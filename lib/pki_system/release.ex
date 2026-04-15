defmodule PkiSystem.Release do
  @moduledoc """
  Release tasks for the consolidated 3-release deployment.

  Usage from a release binary:

      bin/pki_engines eval "PkiSystem.Release.migrate()"
      bin/pki_engines eval "PkiSystem.Release.rollback(PkiCaEngine.Repo, 20260101000000)"

  In schema-per-tenant mode, only the platform repo is migrated globally.
  CA/RA/Validation/Audit engine migrations are tenant-scoped — they run
  per-prefix via PkiPlatformEngine.Provisioner.run_tenant_migrations at
  tenant creation. Running them against the shared pki_platform DB's
  public schema would create stale duplicate tables.
  """

  @platform_repos [PkiPlatformEngine.PlatformRepo]

  def migrate do
    ensure_started()

    for repo <- @platform_repos do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end

    :ok
  end

  def rollback(repo, version) do
    ensure_started()
    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end

  defp ensure_started do
    Application.ensure_all_started(:ssl)
    Application.ensure_all_started(:postgrex)
    Application.ensure_all_started(:ecto_sql)
  end
end
