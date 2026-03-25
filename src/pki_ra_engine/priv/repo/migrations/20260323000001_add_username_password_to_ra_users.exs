defmodule PkiRaEngine.Repo.Migrations.AddUsernamePasswordToRaUsers do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :username, :string
      add :password_hash, :string
    end

    create unique_index(:ra_users, [:username])
  end
end
