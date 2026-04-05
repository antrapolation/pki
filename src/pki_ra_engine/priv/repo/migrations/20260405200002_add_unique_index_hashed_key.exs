defmodule PkiRaEngine.Repo.Migrations.AddUniqueIndexHashedKey do
  use Ecto.Migration

  def change do
    create unique_index(:ra_api_keys, [:hashed_key])
  end
end
