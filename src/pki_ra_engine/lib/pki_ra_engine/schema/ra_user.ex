defmodule PkiRaEngine.Schema.RaUser do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @roles ["ra_admin", "ra_officer", "auditor"]
  @statuses ["active", "suspended"]

  schema "ra_users" do
    field :username, :string
    field :password_hash, :string
    field :password, :string, virtual: true
    field :display_name, :string
    field :role, :string
    field :status, :string, default: "active"
    field :must_change_password, :boolean, default: false
    field :credential_expires_at, :utc_datetime
    field :tenant_id, :binary_id

    has_many :credentials, PkiRaEngine.CredentialManager.Credential, foreign_key: :user_id
    has_many :api_keys, PkiRaEngine.Schema.RaApiKey
    has_many :reviewed_requests, PkiRaEngine.Schema.CsrRequest, foreign_key: :reviewed_by

    timestamps()
  end

  def changeset(ra_user, attrs) do
    ra_user
    |> cast(attrs, [:username, :display_name, :role, :status, :tenant_id, :must_change_password, :credential_expires_at])
    |> validate_required([:role])
    |> validate_inclusion(:role, @roles)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint([:username, :tenant_id])
    |> maybe_generate_id()
  end

  def registration_changeset(ra_user, attrs) do
    ra_user
    |> cast(attrs, [:username, :password, :display_name, :role, :tenant_id, :must_change_password, :credential_expires_at])
    |> validate_required([:username, :password, :role])
    |> validate_length(:username, min: 3, max: 50)
    |> validate_length(:password, min: 8, max: 100)
    |> validate_inclusion(:role, @roles)
    |> unique_constraint([:username, :tenant_id])
    |> hash_password()
    |> maybe_generate_id()
  end

  def password_changeset(user, attrs) do
    user
    |> cast(attrs, [:password, :must_change_password])
    |> validate_required([:password])
    |> validate_length(:password, min: 8)
    |> hash_password_and_clear_expiry()
  end

  def roles, do: @roles
  def statuses, do: @statuses

  defp hash_password_and_clear_expiry(%{valid?: true, changes: %{password: password}} = changeset) do
    changeset
    |> put_change(:password_hash, Argon2.hash_pwd_salt(password))
    |> put_change(:credential_expires_at, nil)
    |> delete_change(:password)
  end

  defp hash_password_and_clear_expiry(changeset), do: changeset

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
