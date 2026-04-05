defmodule PkiRaEngine.Repo.Migrations.AddApprovalModeToCertProfiles do
  use Ecto.Migration

  def change do
    alter table(:cert_profiles) do
      add :approval_mode, :string, default: "manual", null: false
    end
  end
end
