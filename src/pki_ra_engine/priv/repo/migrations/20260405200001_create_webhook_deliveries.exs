defmodule PkiRaEngine.Repo.Migrations.CreateWebhookDeliveries do
  use Ecto.Migration

  def change do
    create table(:webhook_deliveries, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :api_key_id, :binary_id, null: false
      add :csr_id, :binary_id
      add :event, :string, null: false
      add :url, :string, null: false
      add :status, :string, null: false, default: "pending"
      add :attempts, :integer, default: 0
      add :last_http_status, :integer
      add :last_error, :text
      add :payload, :map

      timestamps()
    end

    create index(:webhook_deliveries, [:api_key_id])
    create index(:webhook_deliveries, [:csr_id])
    create index(:webhook_deliveries, [:status])
    create index(:webhook_deliveries, [:inserted_at])
  end
end
