defmodule PkiRaEngine.Repo.Migrations.AddEmailToRaUsers do
  use Ecto.Migration

  def change do
    alter table(:ra_users) do
      add :email, :string
    end
  end
end
