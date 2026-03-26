defmodule PkiCaEngine.KeyVault.ManagedKeypair do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @protection_modes ["credential_own", "split_auth_token", "split_key"]
  @statuses ["pending", "active", "suspended", "archived"]

  schema "managed_keypairs" do
    field :name, :string
    field :algorithm, :string
    field :protection_mode, :string
    field :public_key, :binary
    field :encrypted_private_key, :binary
    field :encrypted_password, :binary
    field :acl_kem_ciphertext, :binary
    field :threshold_k, :integer
    field :threshold_n, :integer
    field :status, :string, default: "pending"
    field :metadata, :map, default: %{}

    belongs_to :ca_instance, PkiCaEngine.Schema.CaInstance

    has_many :grants, PkiCaEngine.KeyVault.KeypairGrant, foreign_key: :managed_keypair_id

    timestamps()
  end

  def changeset(keypair, attrs) do
    keypair
    |> cast(attrs, [
      :name,
      :algorithm,
      :protection_mode,
      :public_key,
      :encrypted_private_key,
      :encrypted_password,
      :acl_kem_ciphertext,
      :threshold_k,
      :threshold_n,
      :status,
      :metadata,
      :ca_instance_id
    ])
    |> validate_required([:name, :algorithm, :protection_mode, :public_key, :ca_instance_id])
    |> validate_inclusion(:protection_mode, @protection_modes)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint([:ca_instance_id, :name])
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
