defmodule PkiPlatformEngine.PlatformAdmin do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "platform_admins" do
    field :username, :string
    field :password_hash, :string
    field :password, :string, virtual: true
    field :display_name, :string
    field :role, :string, default: "super_admin"
    field :status, :string, default: "active"
    field :email, :string
    field :must_change_password, :boolean, default: false
    field :credential_expires_at, :utc_datetime

    timestamps()
  end

  def changeset(admin, attrs) do
    admin
    |> cast(attrs, [:username, :display_name, :status, :email])
    |> validate_required([:username, :display_name])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email address")
    |> unique_constraint(:username)
    |> validate_inclusion(:status, ["active", "suspended"])
  end

  def registration_changeset(admin, attrs) do
    admin
    |> cast(attrs, [:username, :display_name, :password, :email])
    |> validate_required([:username, :display_name, :password])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email address")
    |> validate_length(:password, min: 8, max: 100)
    |> unique_constraint(:username)
    |> maybe_put_id()
    |> hash_password()
  end

  def profile_changeset(admin, attrs) do
    admin
    |> cast(attrs, [:display_name, :email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email address")
  end

  def password_changeset(admin, attrs) do
    admin
    |> cast(attrs, [:password, :must_change_password])
    |> validate_required([:password])
    |> validate_length(:password, min: 8, max: 100)
    |> hash_password()
  end

  def invitation_changeset(admin, attrs) do
    admin
    |> cast(attrs, [:username, :display_name, :email, :password, :must_change_password, :credential_expires_at])
    |> validate_required([:username, :display_name, :email, :password])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email address")
    |> validate_length(:password, min: 8, max: 100)
    |> unique_constraint(:username)
    |> unique_constraint(:email)
    |> maybe_put_id()
    |> hash_password()
  end

  defp maybe_put_id(%{data: %{id: nil}} = changeset) do
    put_change(changeset, :id, Uniq.UUID.uuid7())
  end

  defp maybe_put_id(changeset), do: changeset

  defp hash_password(%{valid?: true, changes: %{password: password}} = changeset) do
    put_change(changeset, :password_hash, Argon2.hash_pwd_salt(password))
  end

  defp hash_password(changeset), do: changeset
end
