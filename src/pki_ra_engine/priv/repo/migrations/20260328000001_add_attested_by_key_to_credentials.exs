defmodule PkiRaEngine.Repo.Migrations.AddAttestedByKeyToCredentials do
  use Ecto.Migration

  def change do
    alter table(:credentials) do
      add :attested_by_key, :binary
    end
  end
end
