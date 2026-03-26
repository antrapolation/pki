defmodule PkiRaEngine.CredentialManager.Credential do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @credential_types ["signing", "kem"]
  @statuses ["active", "revoked"]

  schema "credentials" do
    field :credential_type, :string
    field :algorithm, :string
    field :public_key, :binary
    field :encrypted_private_key, :binary
    field :salt, :binary
    field :certificate, :binary
    field :status, :string, default: "active"

    belongs_to :user, PkiRaEngine.Schema.RaUser

    timestamps()
  end

  def changeset(credential, attrs) do
    credential
    |> cast(attrs, [:credential_type, :algorithm, :public_key, :encrypted_private_key, :salt, :certificate, :status, :user_id])
    |> validate_required([:credential_type, :algorithm, :public_key, :encrypted_private_key, :salt, :user_id])
    |> validate_inclusion(:credential_type, @credential_types)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:user_id)
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
