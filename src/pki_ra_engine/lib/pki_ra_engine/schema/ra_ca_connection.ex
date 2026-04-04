defmodule PkiRaEngine.Schema.RaCaConnection do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["active", "revoked"]

  schema "ra_ca_connections" do
    field :issuer_key_id, :string
    field :issuer_key_name, :string
    field :algorithm, :string
    field :ca_instance_name, :string
    field :status, :string, default: "active"
    field :connected_at, :utc_datetime
    field :connected_by, :binary_id

    belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance

    timestamps()
  end

  @required_fields [:ra_instance_id, :issuer_key_id, :connected_at]
  @optional_fields [:issuer_key_name, :algorithm, :ca_instance_name, :status, :connected_by]

  def changeset(connection, attrs) do
    connection
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint([:ra_instance_id, :issuer_key_id])
    |> foreign_key_constraint(:ra_instance_id)
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
