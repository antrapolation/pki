defmodule PkiSystem.Release do
  @moduledoc """
  Release tasks for the consolidated 3-release deployment.

  Usage from a release binary:

      bin/pki_engines eval "PkiSystem.Release.migrate()"
      bin/pki_engines eval "PkiSystem.Release.rollback(PkiCaEngine.Repo, 20260101000000)"

  Runs migrations for all databases: platform, CA engine, RA engine,
  validation, and audit trail.
  """

  @repos [
    PkiPlatformEngine.PlatformRepo,
    PkiCaEngine.Repo,
    PkiRaEngine.Repo,
    PkiValidation.Repo,
    PkiAuditTrail.Repo
  ]

  def migrate do
    ensure_started()

    for repo <- @repos do
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
