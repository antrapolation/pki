defmodule PkiPlatformEngine.PlatformRepo.Migrations.ReplaceAlgoFieldsWithMaxCaDepth do
  use Ecto.Migration

  def change do
    alter table(:tenants) do
      remove :signing_algorithm, :string, default: "ECC-P256"
      remove :kem_algorithm, :string, default: "ECDH-P256"
      add :max_ca_depth, :integer, default: 2, null: false
    end
  end
end
