defmodule PkiCaEngine.Schema.ThresholdShare do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "threshold_shares" do
    field :share_index, :integer
    field :encrypted_share, :binary
    field :min_shares, :integer
    field :total_shares, :integer
    field :key_label, :string
    field :status, :string, default: "pending"
    field :accepted_at, :utc_datetime
    field :encrypted_password, :binary

    belongs_to :issuer_key, PkiCaEngine.Schema.IssuerKey
    # custodian_user_id stores platform user ID (no FK — users live in platform DB)
    field :custodian_user_id, :binary_id

    timestamps()
  end

  def changeset(share, attrs) do
    share
    |> cast(attrs, [:issuer_key_id, :custodian_user_id, :share_index, :encrypted_share, :min_shares, :total_shares, :key_label, :status, :accepted_at])
    |> validate_required([:issuer_key_id, :custodian_user_id, :share_index, :encrypted_share, :min_shares, :total_shares])
    |> foreign_key_constraint(:issuer_key_id)
    |> unique_constraint([:issuer_key_id, :custodian_user_id, :share_index])
    |> maybe_generate_id()
  end

  def placeholder_changeset(share, attrs) do
    share
    |> cast(attrs, [:issuer_key_id, :custodian_user_id, :share_index, :min_shares, :total_shares, :key_label, :status, :accepted_at])
    |> validate_required([:issuer_key_id, :custodian_user_id, :share_index, :min_shares, :total_shares])
    |> foreign_key_constraint(:issuer_key_id)
    |> unique_constraint([:issuer_key_id, :custodian_user_id, :share_index])
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
