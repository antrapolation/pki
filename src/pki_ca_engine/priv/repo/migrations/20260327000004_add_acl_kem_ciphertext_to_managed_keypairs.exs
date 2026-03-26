defmodule PkiCaEngine.Repo.Migrations.AddAclKemCiphertextToManagedKeypairs do
  use Ecto.Migration

  def change do
    alter table(:managed_keypairs) do
      add :acl_kem_ciphertext, :binary
    end
  end
end
