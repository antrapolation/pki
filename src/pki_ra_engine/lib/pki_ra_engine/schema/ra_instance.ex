defmodule PkiRaEngine.Schema.RaInstance do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["initialized", "active", "suspended"]

  schema "ra_instances" do
    field :name, :string
    field :status, :string, default: "initialized"
    field :created_by, :string

    has_many :ra_users, PkiRaEngine.Schema.RaUser
    has_many :cert_profiles, PkiRaEngine.Schema.CertProfile
    has_many :ra_api_keys, PkiRaEngine.Schema.RaApiKey

    timestamps()
  end

  def changeset(instance, attrs) do
    instance
    |> cast(attrs, [:name, :status, :created_by])
    |> validate_required([:name])
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:name)
    |> maybe_generate_id()
  end

  def statuses, do: @statuses

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
