defmodule PkiRaEngine.Schema.DcvChallenge do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @statuses ["pending", "passed", "failed", "expired"]
  @methods ["http-01", "dns-01"]

  schema "dcv_challenges" do
    field :domain, :string
    field :method, :string
    field :token, :string
    field :token_value, :string
    field :status, :string, default: "pending"
    field :initiated_by, :binary_id
    field :verified_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :attempts, :integer, default: 0
    field :last_checked_at, :utc_datetime
    field :error_details, :string

    belongs_to :csr_request, PkiRaEngine.Schema.CsrRequest, foreign_key: :csr_id

    timestamps()
  end

  @required_fields [:csr_id, :domain, :method, :token, :token_value, :expires_at]
  @optional_fields [
    :status,
    :initiated_by,
    :verified_at,
    :attempts,
    :last_checked_at,
    :error_details
  ]

  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:method, @methods)
    |> foreign_key_constraint(:csr_id)
    |> unique_constraint([:csr_id, :domain, :method])
    |> maybe_generate_id()
  end

  def statuses, do: @statuses
  def methods, do: @methods

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
