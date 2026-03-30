defmodule PkiPlatformEngine.UserProfile do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "user_profiles" do
    field :username, :string
    field :password, :string, virtual: true
    field :password_hash, :string
    field :display_name, :string
    field :email, :string
    field :status, :string, default: "active"
    field :must_change_password, :boolean
    field :credential_expires_at, :utc_datetime

    has_many :tenant_roles, PkiPlatformEngine.UserTenantRole

    timestamps()
  end

  def changeset(user, attrs) do
    user
    |> cast(attrs, [:username, :display_name, :email, :status, :must_change_password, :credential_expires_at])
    |> validate_required([:username])
    |> validate_length(:username, min: 3, max: 50)
    |> unique_constraint(:username)
    |> maybe_generate_id()
  end

  def registration_changeset(user, attrs) do
    user
    |> cast(attrs, [:username, :display_name, :email, :status, :must_change_password, :credential_expires_at, :password])
    |> validate_required([:username, :password])
    |> validate_length(:username, min: 3, max: 50)
    |> validate_length(:password, min: 8, max: 100)
    |> unique_constraint(:username)
    |> maybe_generate_id()
    |> hash_password()
  end

  def password_changeset(user, attrs) do
    user
    |> cast(attrs, [:password, :must_change_password])
    |> validate_required([:password])
    |> validate_length(:password, min: 8, max: 100)
    |> put_change(:credential_expires_at, nil)
    |> hash_password()
  end

  defp hash_password(%{valid?: true, changes: %{password: password}} = changeset) do
    changeset
    |> put_change(:password_hash, Argon2.hash_pwd_salt(password))
    |> delete_change(:password)
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
