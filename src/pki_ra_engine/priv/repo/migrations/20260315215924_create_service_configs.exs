defmodule PkiRaEngine.Repo.Migrations.CreateServiceConfigs do
  use Ecto.Migration

  def change do
    create table(:service_configs) do
      add :service_type, :string, null: false
      add :port, :integer
      add :url, :string
      add :rate_limit, :integer
      add :ip_whitelist, :map, default: %{}
      add :ip_blacklist, :map, default: %{}
      add :connection_security, :string
      add :credentials, :binary
      add :ca_engine_ref, :string

      timestamps()
    end

    create unique_index(:service_configs, [:service_type])
  end
end
