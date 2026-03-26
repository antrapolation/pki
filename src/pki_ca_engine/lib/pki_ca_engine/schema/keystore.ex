defmodule PkiCaEngine.Schema.Keystore do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @types ["software", "hsm"]
  @statuses ["active", "inactive"]

  schema "keystores" do
    field :type, :string
    field :config, :binary
    field :status, :string, default: "active"
    field :provider_name, :string

    belongs_to :ca_instance, PkiCaEngine.Schema.CaInstance

    has_many :key_ceremonies, PkiCaEngine.Schema.KeyCeremony

    timestamps()
  end

  def changeset(keystore, attrs) do
    keystore
    |> cast(attrs, [:ca_instance_id, :type, :config, :status, :provider_name])
    |> validate_required([:ca_instance_id, :type])
    |> validate_inclusion(:type, @types)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:ca_instance_id)
    |> maybe_generate_id()
  end

  def update_changeset(keystore, attrs) do
    keystore
    |> cast(attrs, [:config, :status, :provider_name])
    |> validate_inclusion(:status, @statuses)
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
