defmodule PkiPlatformEngine.TenantHsmAccess do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "tenant_hsm_access" do
    belongs_to :tenant, PkiPlatformEngine.Tenant
    belongs_to :hsm_device, PkiPlatformEngine.HsmDevice

    timestamps()
  end

  def changeset(access, attrs) do
    access
    |> cast(attrs, [:tenant_id, :hsm_device_id])
    |> validate_required([:tenant_id, :hsm_device_id])
    |> unique_constraint([:tenant_id, :hsm_device_id])
    |> foreign_key_constraint(:tenant_id)
    |> foreign_key_constraint(:hsm_device_id)
    |> maybe_generate_id()
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
