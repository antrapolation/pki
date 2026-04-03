defmodule PkiCaEngine.Repo.Migrations.MakeEncryptedShareNullable do
  use Ecto.Migration

  def change do
    alter table(:threshold_shares) do
      modify :encrypted_share, :binary, null: true
    end
  end
end
