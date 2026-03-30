defmodule PkiRaEngine.Schema.RaApiKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["active", "revoked"]

  schema "ra_api_keys" do
    field :hashed_key, :string
    field :label, :string
    field :expiry, :utc_datetime_usec
    field :rate_limit, :integer
    field :status, :string, default: "active"
    field :revoked_at, :utc_datetime_usec

    belongs_to :ra_user, PkiRaEngine.Schema.RaUser
    belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance

    timestamps()
  end

  @required_fields [:hashed_key, :ra_user_id]
  @optional_fields [:label, :expiry, :rate_limit, :status, :revoked_at, :ra_instance_id]

  def changeset(api_key, attrs) do
    api_key
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:ra_user_id)
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
