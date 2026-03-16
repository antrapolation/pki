defmodule PkiCaEngine.Schema.ThresholdShare do
  use Ecto.Schema
  import Ecto.Changeset

  schema "threshold_shares" do
    field :share_index, :integer
    field :encrypted_share, :binary
    field :min_shares, :integer
    field :total_shares, :integer

    belongs_to :issuer_key, PkiCaEngine.Schema.IssuerKey
    belongs_to :custodian_user, PkiCaEngine.Schema.CaUser, foreign_key: :custodian_user_id

    timestamps()
  end

  def changeset(share, attrs) do
    share
    |> cast(attrs, [:issuer_key_id, :custodian_user_id, :share_index, :encrypted_share, :min_shares, :total_shares])
    |> validate_required([:issuer_key_id, :custodian_user_id, :share_index, :encrypted_share, :min_shares, :total_shares])
    |> foreign_key_constraint(:issuer_key_id)
    |> foreign_key_constraint(:custodian_user_id)
    |> unique_constraint([:issuer_key_id, :custodian_user_id])
  end
end
