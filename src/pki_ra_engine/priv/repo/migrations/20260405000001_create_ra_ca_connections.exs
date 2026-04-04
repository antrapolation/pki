defmodule PkiRaEngine.Repo.Migrations.CreateRaCaConnections do
  use Ecto.Migration

  def change do
    create table(:ra_ca_connections, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ra_instance_id, references(:ra_instances, type: :binary_id, on_delete: :delete_all), null: false
      add :issuer_key_id, :string, null: false
      add :issuer_key_name, :string
      add :algorithm, :string
      add :ca_instance_name, :string
      add :status, :string, default: "active", null: false
      add :connected_at, :utc_datetime, null: false
      add :connected_by, :binary_id

      timestamps()
    end

    create unique_index(:ra_ca_connections, [:ra_instance_id, :issuer_key_id])
    create index(:ra_ca_connections, [:status])
  end
end
