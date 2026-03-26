defmodule PkiCaEngine.Schema.CaUser do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @roles ["ca_admin", "key_manager", "ra_admin", "auditor"]
  @statuses ["active", "suspended"]

  schema "ca_users" do
    field :username, :string
    field :password_hash, :string
    field :password, :string, virtual: true
    field :display_name, :string
    field :role, :string
    field :status, :string, default: "active"

    belongs_to :ca_instance, PkiCaEngine.Schema.CaInstance

    has_many :credentials, PkiCaEngine.CredentialManager.Credential, foreign_key: :user_id
    has_many :keypair_accesses, PkiCaEngine.Schema.KeypairAccess, foreign_key: :user_id
    has_many :threshold_shares, PkiCaEngine.Schema.ThresholdShare, foreign_key: :custodian_user_id

    timestamps()
  end

  def changeset(user, attrs) do
    user
    |> cast(attrs, [:ca_instance_id, :username, :display_name, :role, :status])
    |> validate_required([:ca_instance_id, :role])
    |> validate_inclusion(:role, @roles)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:ca_instance_id)
    |> unique_constraint(:username)
    |> maybe_generate_id()
  end

  def registration_changeset(user, attrs) do
    user
    |> cast(attrs, [:ca_instance_id, :username, :password, :display_name, :role])
    |> validate_required([:ca_instance_id, :username, :password, :role])
    |> validate_length(:username, min: 3, max: 50)
    |> validate_length(:password, min: 8, max: 100)
    |> validate_inclusion(:role, @roles)
    |> unique_constraint(:username)
    |> foreign_key_constraint(:ca_instance_id)
    |> hash_password()
    |> maybe_generate_id()
  end

  def update_changeset(user, attrs) do
    user
    |> cast(attrs, [:display_name, :status])
    |> validate_inclusion(:status, @statuses)
  end

  defp hash_password(%{valid?: true, changes: %{password: password}} = changeset) do
    put_change(changeset, :password_hash, Argon2.hash_pwd_salt(password))
  end

  defp hash_password(changeset), do: changeset

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
