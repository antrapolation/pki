defmodule PkiCaEngine.Schema.KeypairAccess do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "keypair_access" do
    field :granted_at, :utc_datetime

    belongs_to :issuer_key, PkiCaEngine.Schema.IssuerKey
    belongs_to :user, PkiCaEngine.Schema.CaUser
    belongs_to :granter, PkiCaEngine.Schema.CaUser, foreign_key: :granted_by
  end

  def changeset(access, attrs) do
    access
    |> cast(attrs, [:issuer_key_id, :user_id, :granted_by, :granted_at])
    |> validate_required([:issuer_key_id, :user_id, :granted_at])
    |> foreign_key_constraint(:issuer_key_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:granted_by)
    |> unique_constraint([:issuer_key_id, :user_id])
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
