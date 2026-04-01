defmodule PkiPlatformEngine.PlatformRepo.Migrations.CreateHsmDevices do
  use Ecto.Migration

  def change do
    create table(:hsm_devices, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :label, :string, null: false
      add :pkcs11_lib_path, :string, null: false
      add :slot_id, :integer, null: false, default: 0
      add :manufacturer, :string
      add :status, :string, null: false, default: "active"

      timestamps()
    end

    create unique_index(:hsm_devices, [:label])

    create table(:tenant_hsm_access, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :tenant_id, references(:tenants, type: :binary_id, on_delete: :delete_all), null: false
      add :hsm_device_id, references(:hsm_devices, type: :binary_id, on_delete: :restrict), null: false

      timestamps()
    end

    create unique_index(:tenant_hsm_access, [:tenant_id, :hsm_device_id])
    create index(:tenant_hsm_access, [:tenant_id])
  end
end
