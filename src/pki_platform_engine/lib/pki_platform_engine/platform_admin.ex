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

    timestamps()
  end

  def changeset(admin, attrs) do
    admin
    |> cast(attrs, [:username, :display_name, :status])
    |> validate_required([:username, :display_name])
    |> unique_constraint(:username)
    |> validate_inclusion(:status, ["active", "suspended"])
  end

  def registration_changeset(admin, attrs) do
    admin
    |> cast(attrs, [:username, :display_name, :password])
    |> validate_required([:username, :display_name, :password])
    |> validate_length(:password, min: 8)
    |> unique_constraint(:username)
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
