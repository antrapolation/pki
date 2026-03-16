defmodule PkiRaEngine.Schema.RaUser do
  use Ecto.Schema
  import Ecto.Changeset

  @roles ["ra_admin", "ra_officer", "auditor"]
  @statuses ["active", "suspended"]

  schema "ra_users" do
    field :did, :string
    field :display_name, :string
    field :role, :string
    field :status, :string, default: "active"

    has_many :api_keys, PkiRaEngine.Schema.RaApiKey
    has_many :reviewed_requests, PkiRaEngine.Schema.CsrRequest, foreign_key: :reviewed_by

    timestamps()
  end

  @required_fields [:did, :role]
  @optional_fields [:display_name, :status]

  def changeset(ra_user, attrs) do
    ra_user
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:role, @roles)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:did)
  end

  def roles, do: @roles
  def statuses, do: @statuses
end
