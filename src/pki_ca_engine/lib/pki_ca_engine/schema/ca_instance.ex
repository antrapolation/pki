defmodule PkiCaEngine.Schema.CaInstance do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["initialized", "active", "suspended"]

  schema "ca_instances" do
    field :name, :string
    field :status, :string, default: "initialized"
    field :domain_info, :map, default: %{}
    field :created_by, :string

    has_many :ca_users, PkiCaEngine.Schema.CaUser
    has_many :keystores, PkiCaEngine.Schema.Keystore
    has_many :issuer_keys, PkiCaEngine.Schema.IssuerKey
    has_many :key_ceremonies, PkiCaEngine.Schema.KeyCeremony

    timestamps()
  end

  def changeset(instance, attrs) do
    instance
    |> cast(attrs, [:name, :status, :domain_info, :created_by])
    |> validate_required([:name])
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:name)
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
