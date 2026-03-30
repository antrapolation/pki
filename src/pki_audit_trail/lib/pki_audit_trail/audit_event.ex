defmodule PkiAuditTrail.AuditEvent do
  use Ecto.Schema
  import Ecto.Changeset

  @required_fields [
    :event_id,
    :timestamp,
    :node_name,
    :actor_did,
    :actor_role,
    :action,
    :resource_type,
    :resource_id,
    :prev_hash,
    :event_hash
  ]
  @optional_fields [:details, :ca_instance_id]

  schema "audit_events" do
    field :event_id, Ecto.UUID
    field :timestamp, :utc_datetime_usec
    field :node_name, :string
    field :actor_did, :string
    field :actor_role, :string
    field :action, :string
    field :resource_type, :string
    field :resource_id, :string
    field :details, :map, default: %{}
    field :ca_instance_id, :string
    field :prev_hash, :string
    field :event_hash, :string
  end

  def changeset(audit_event, attrs) do
    audit_event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> unique_constraint(:event_id)
  end
end
