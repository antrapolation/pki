defmodule PkiPlatformEngine.PlatformAuditEvent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "platform_audit_events" do
    field :timestamp, :utc_datetime_usec
    field :actor_id, :binary_id
    field :actor_username, :string
    field :action, :string
    field :target_type, :string
    field :target_id, :binary_id
    field :tenant_id, :binary_id
    field :portal, :string
    field :details, :map, default: %{}

    timestamps(updated_at: false)
  end

  @actions ~w(login login_failed user_created user_suspended user_activated user_deleted password_reset password_changed profile_updated)

  def changeset(event, attrs) do
    event
    |> cast(attrs, [:timestamp, :actor_id, :actor_username, :action, :target_type, :target_id, :tenant_id, :portal, :details])
    |> validate_required([:timestamp, :action])
    |> validate_inclusion(:action, @actions)
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
