defmodule PkiRaEngine.Schema.RaApiKey do
  use Ecto.Schema
  import Ecto.Changeset

  @statuses ["active", "revoked"]

  schema "ra_api_keys" do
    field :hashed_key, :string
    field :label, :string
    field :expiry, :utc_datetime_usec
    field :rate_limit, :integer
    field :status, :string, default: "active"
    field :revoked_at, :utc_datetime_usec

    belongs_to :ra_user, PkiRaEngine.Schema.RaUser

    timestamps()
  end

  @required_fields [:hashed_key, :ra_user_id]
  @optional_fields [:label, :expiry, :rate_limit, :status, :revoked_at]

  def changeset(api_key, attrs) do
    api_key
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:ra_user_id)
  end

  def statuses, do: @statuses
end
