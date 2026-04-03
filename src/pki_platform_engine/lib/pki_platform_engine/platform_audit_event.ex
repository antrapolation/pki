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

  @actions ~w(
    login login_failed
    user_created user_suspended user_activated user_deleted
    password_reset password_changed profile_updated
    invitation_resent
    ca_instance_created ca_instance_renamed ca_instance_activated ca_instance_suspended
    keystore_configured
    hsm_device_probed
    ceremony_initiated ceremony_keypair_generated ceremony_shares_distributed
    ceremony_completed ceremony_cancelled ceremony_deleted
    issuer_key_activated csr_signed
    quick_setup_completed quick_setup_failed
  )

  # login_failed may not have an actor (unknown username attempt)
  @system_actions ~w(login login_failed)

  def changeset(event, attrs) do
    event
    |> cast(attrs, [:timestamp, :actor_id, :actor_username, :action, :target_type, :target_id, :tenant_id, :portal, :details])
    |> validate_required([:timestamp, :action])
    |> validate_inclusion(:action, @actions)
    |> require_actor_for_user_actions()
    |> maybe_generate_id()
  end

  defp require_actor_for_user_actions(changeset) do
    action = get_field(changeset, :action)

    if action in @system_actions do
      changeset
    else
      validate_required(changeset, [:actor_id, :actor_username])
    end
  end

  defp maybe_generate_id(changeset) do
    if get_field(changeset, :id) do
      changeset
    else
      put_change(changeset, :id, Uniq.UUID.uuid7())
    end
  end
end
