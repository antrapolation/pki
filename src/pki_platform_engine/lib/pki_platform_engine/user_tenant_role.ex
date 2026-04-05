defmodule PkiPlatformEngine.UserTenantRole do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "user_tenant_roles" do
    belongs_to :user_profile, PkiPlatformEngine.UserProfile
    belongs_to :tenant, PkiPlatformEngine.Tenant

    field :role, :string
    field :portal, :string
    field :ca_instance_id, :string
    field :status, :string, default: "active"

    timestamps()
  end

  def changeset(role, attrs) do
    role
    |> cast(attrs, [:user_profile_id, :tenant_id, :role, :portal, :ca_instance_id, :status])
    |> validate_required([:user_profile_id, :tenant_id, :role, :portal])
    |> validate_inclusion(:role, ["ca_admin", "key_manager", "ra_admin", "ra_officer", "auditor", "tenant_admin"])
    |> validate_inclusion(:portal, ["ca", "ra", "platform"])
    |> validate_inclusion(:status, ["active", "suspended"])
    |> foreign_key_constraint(:user_profile_id)
    |> foreign_key_constraint(:tenant_id)
    |> unique_constraint([:user_profile_id, :tenant_id, :role, :portal])
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
