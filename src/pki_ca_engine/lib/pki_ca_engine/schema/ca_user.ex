defmodule PkiCaEngine.Schema.CaUser do
  use Ecto.Schema
  import Ecto.Changeset

  @roles ["ca_admin", "key_manager", "ra_admin", "auditor"]
  @statuses ["active", "suspended"]

  schema "ca_users" do
    field :did, :string
    field :display_name, :string
    field :role, :string
    field :status, :string, default: "active"

    belongs_to :ca_instance, PkiCaEngine.Schema.CaInstance

    has_many :keypair_accesses, PkiCaEngine.Schema.KeypairAccess, foreign_key: :user_id
    has_many :threshold_shares, PkiCaEngine.Schema.ThresholdShare, foreign_key: :custodian_user_id

    timestamps()
  end

  def changeset(user, attrs) do
    user
    |> cast(attrs, [:ca_instance_id, :did, :display_name, :role, :status])
    |> validate_required([:ca_instance_id, :did, :role])
    |> validate_inclusion(:role, @roles)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:ca_instance_id)
    |> unique_constraint([:ca_instance_id, :did])
  end

  def update_changeset(user, attrs) do
    user
    |> cast(attrs, [:display_name, :status])
    |> validate_inclusion(:status, @statuses)
  end
end
