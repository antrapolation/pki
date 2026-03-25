defmodule PkiCaEngine.Repo.Migrations.AddUsernamePasswordToCaUsers do
  use Ecto.Migration

  def change do
    alter table(:ca_users) do
      add :username, :string
      add :password_hash, :string
    end

    create unique_index(:ca_users, [:username])
  end
end
