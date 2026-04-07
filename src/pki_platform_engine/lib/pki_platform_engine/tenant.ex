defmodule PkiPlatformEngine.Tenant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}

  schema "tenants" do
    field :name, :string
    field :slug, :string
    field :database_name, :string
    field :status, :string, default: "initialized"
    field :max_ca_depth, :integer, default: 2
    field :email, :string
    field :metadata, :map, default: %{}
    timestamps()
  end

  @statuses ["initialized", "active", "suspended"]

  def changeset(tenant, attrs) do
    tenant
    |> cast(attrs, [:name, :slug, :status, :max_ca_depth, :email, :metadata])
    |> validate_required([:name, :slug, :email])
    |> validate_format(:email, ~r/@/)
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:max_ca_depth, greater_than: 0)
    |> validate_format(:slug, ~r/^[a-z0-9][a-z0-9-]*[a-z0-9]$/, message: "must be lowercase alphanumeric with hyphens")
    |> unique_constraint(:slug)
    |> unique_constraint(:name)
    |> maybe_generate_id()
    |> maybe_generate_database_name()
  end

  def status_changeset(tenant, attrs) do
    tenant
    |> cast(attrs, [:status])
    |> validate_required([:status])
    |> validate_inclusion(:status, @statuses)
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end

  defp maybe_generate_database_name(changeset) do
    if get_field(changeset, :database_name) do
      changeset
    else
      id = get_field(changeset, :id)
      db_name = "pki_tenant_" <> String.replace(id, "-", "")
      put_change(changeset, :database_name, db_name)
    end
  end
end
