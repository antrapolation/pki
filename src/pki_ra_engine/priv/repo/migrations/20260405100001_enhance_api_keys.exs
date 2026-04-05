defmodule PkiRaEngine.Repo.Migrations.EnhanceApiKeys do
  use Ecto.Migration

  def change do
    alter table(:ra_api_keys) do
      add :key_type, :string, default: "client", null: false
      add :allowed_profile_ids, :jsonb, default: "[]"
      add :ip_whitelist, :jsonb, default: "[]"
      add :webhook_url, :string
      add :webhook_secret, :string
    end

    create index(:ra_api_keys, [:key_type])
  end
end
