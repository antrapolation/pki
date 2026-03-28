defmodule PkiCaEngine.KeyVault.KeypairGrant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "keypair_grants" do
    field :signed_envelope, :binary
    field :granted_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec

    belongs_to :managed_keypair, PkiCaEngine.KeyVault.ManagedKeypair
    belongs_to :credential, PkiCaEngine.CredentialManager.Credential

    timestamps()
  end

  def changeset(grant, attrs) do
    grant
    |> cast(attrs, [:signed_envelope, :granted_at, :revoked_at, :managed_keypair_id, :credential_id])
    |> validate_required([:signed_envelope, :granted_at, :managed_keypair_id, :credential_id])
    |> foreign_key_constraint(:managed_keypair_id)
    |> foreign_key_constraint(:credential_id)
    |> unique_constraint([:managed_keypair_id, :credential_id])
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
