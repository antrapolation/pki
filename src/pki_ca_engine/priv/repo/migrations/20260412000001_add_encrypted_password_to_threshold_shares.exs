defmodule PkiCaEngine.Repo.Migrations.AddEncryptedPasswordToThresholdShares do
  use Ecto.Migration

  def change do
    alter table(:threshold_shares) do
      add :encrypted_password, :binary
    end
  end
end
