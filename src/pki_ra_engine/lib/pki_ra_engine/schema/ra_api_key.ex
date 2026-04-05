defmodule PkiRaEngine.Schema.RaApiKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @key_types ["client", "service"]
  @statuses ["active", "revoked"]

  schema "ra_api_keys" do
    field :hashed_key, :string
    field :label, :string
    field :key_type, :string, default: "client"
    field :expiry, :utc_datetime_usec
    field :rate_limit, :integer, default: 60
    field :status, :string, default: "active"
    field :revoked_at, :utc_datetime_usec
    field :allowed_profile_ids, {:array, :string}, default: []
    field :ip_whitelist, {:array, :string}, default: []
    field :webhook_url, :string
    field :webhook_secret, :string

    belongs_to :ra_user, PkiRaEngine.Schema.RaUser
    belongs_to :ra_instance, PkiRaEngine.Schema.RaInstance

    timestamps()
  end

  @required_fields [:hashed_key, :ra_user_id, :key_type]
  @optional_fields [
    :label, :expiry, :rate_limit, :status, :revoked_at, :ra_instance_id,
    :allowed_profile_ids, :ip_whitelist, :webhook_url, :webhook_secret
  ]

  def changeset(api_key, attrs) do
    api_key
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:key_type, @key_types)
    |> validate_length(:label, max: 100)
    |> validate_rate_limit()
    |> foreign_key_constraint(:ra_user_id)
    |> maybe_generate_id()
  end

  def key_types, do: @key_types
  def statuses, do: @statuses

  defp validate_rate_limit(changeset) do
    case get_field(changeset, :rate_limit) do
      nil -> changeset
      rl when rl >= 1 and rl <= 10000 -> changeset
      _ -> add_error(changeset, :rate_limit, "must be between 1 and 10000")
    end
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
