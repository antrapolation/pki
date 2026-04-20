defmodule PkiPlatformEngine.Tenant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}

  schema "tenants" do
    field :name, :string
    field :slug, :string
    field :database_name, :string
    field :schema_mode, :string, default: "schema"
    field :status, :string, default: "initialized"
    field :max_ca_depth, :integer, default: 2
    field :email, :string
    field :metadata, :map, default: %{}
    timestamps()
  end

  @statuses ["initialized", "provisioning", "active", "suspended", "failed"]
  # "beam" = per-tenant BEAM (Mnesia, current architecture).
  # "schema" / "database" are retained for legacy rows; new tenants
  # are always "beam".
  @schema_modes ["beam", "schema", "database"]

  def changeset(tenant, attrs) do
    tenant
    |> cast(attrs, [:name, :slug, :status, :max_ca_depth, :email, :metadata, :schema_mode])
    |> validate_required([:name, :slug, :email])
    |> validate_format(:email, ~r/@/)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:schema_mode, @schema_modes)
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

  @doc """
  Mark a tenant as failed to provision. `reason` is any term; it gets
  stringified into the tenant's metadata under `"failure"` so the
  admin UI can display it and the row can be retried later.
  """
  def failed_changeset(tenant, reason) do
    failure_entry = %{
      "step" => to_string(elem_or(reason, 0, "unknown")),
      "detail" => inspect(reason),
      "at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    new_metadata = Map.put(tenant.metadata || %{}, "failure", failure_entry)

    tenant
    |> cast(%{status: "failed", metadata: new_metadata}, [:status, :metadata])
    |> validate_inclusion(:status, @statuses)
  end

  defp elem_or(tuple, idx, _default) when is_tuple(tuple) and tuple_size(tuple) > idx,
    do: elem(tuple, idx)
  defp elem_or(_, _, default), do: default

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
