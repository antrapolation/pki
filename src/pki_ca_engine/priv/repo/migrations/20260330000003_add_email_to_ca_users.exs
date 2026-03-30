defmodule PkiCaEngine.Repo.Migrations.AddEmailToCaUsers do
  use Ecto.Migration

  def change do
    alter table(:ca_users) do
      add :email, :string
    end
  end
end
