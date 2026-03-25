defmodule PkiRaEngine.Schema.RaUser do
  use Ecto.Schema
  import Ecto.Changeset

  @roles ["ra_admin", "ra_officer", "auditor"]
  @statuses ["active", "suspended"]

  schema "ra_users" do
    field :username, :string
    field :password_hash, :string
    field :password, :string, virtual: true
    field :did, :string
    field :display_name, :string
    field :role, :string
    field :status, :string, default: "active"

    has_many :api_keys, PkiRaEngine.Schema.RaApiKey
    has_many :reviewed_requests, PkiRaEngine.Schema.CsrRequest, foreign_key: :reviewed_by

    timestamps()
  end

  def changeset(ra_user, attrs) do
    ra_user
    |> cast(attrs, [:username, :did, :display_name, :role, :status])
    |> validate_required([:role])
    |> validate_inclusion(:role, @roles)
    |> validate_inclusion(:status, @statuses)
    |> unique_constraint(:username)
    |> unique_constraint(:did)
  end

  def registration_changeset(ra_user, attrs) do
    ra_user
    |> cast(attrs, [:username, :password, :display_name, :role])
    |> validate_required([:username, :password, :role])
    |> validate_length(:username, min: 3, max: 50)
    |> validate_length(:password, min: 8, max: 100)
    |> validate_inclusion(:role, @roles)
    |> unique_constraint(:username)
    |> hash_password()
  end

  def roles, do: @roles
  def statuses, do: @statuses

  defp hash_password(%{valid?: true, changes: %{password: password}} = changeset) do
    put_change(changeset, :password_hash, Argon2.hash_pwd_salt(password))
  end

  defp hash_password(changeset), do: changeset
end
