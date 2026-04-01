defmodule PkiPlatformEngine.HsmDevice do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}

  @statuses ["active", "inactive"]

  schema "hsm_devices" do
    field :label, :string
    field :pkcs11_lib_path, :string
    field :slot_id, :integer, default: 0
    field :manufacturer, :string
    field :status, :string, default: "active"

    timestamps()
  end

  def changeset(device, attrs) do
    device
    |> cast(attrs, [:label, :pkcs11_lib_path, :slot_id, :manufacturer, :status])
    |> validate_required([:label, :pkcs11_lib_path])
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:label)
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
