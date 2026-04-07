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
    field :parent_id, :binary_id
    field :is_offline, :boolean, default: false

    belongs_to :parent, PkiCaEngine.Schema.CaInstance,
      foreign_key: :parent_id,
      define_field: false

    has_many :children, PkiCaEngine.Schema.CaInstance, foreign_key: :parent_id

    has_many :ca_users, PkiCaEngine.Schema.CaUser
    has_many :keystores, PkiCaEngine.Schema.Keystore
    has_many :issuer_keys, PkiCaEngine.Schema.IssuerKey
    has_many :key_ceremonies, PkiCaEngine.Schema.KeyCeremony

    timestamps()
  end

  def changeset(instance, attrs) do
    instance
    |> cast(attrs, [:name, :status, :domain_info, :created_by, :parent_id, :is_offline])
    |> validate_required([:name])
    |> validate_length(:name, max: 100)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:name)
    |> foreign_key_constraint(:parent_id)
    |> freeze_parent_id()
    |> maybe_generate_id()
  end

  defp freeze_parent_id(%{data: %{__meta__: %{state: :loaded}}} = changeset) do
    delete_change(changeset, :parent_id)
  end

  defp freeze_parent_id(changeset), do: changeset

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
