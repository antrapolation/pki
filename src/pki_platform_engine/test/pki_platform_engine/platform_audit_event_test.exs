defmodule PkiPlatformEngine.PlatformAuditEventTest do
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.PlatformAuditEvent

  @valid_actor %{
    actor_id: "11111111-1111-1111-1111-111111111111",
    actor_username: "admin"
  }

  describe "tenant provisioning actions" do
    for action <- ~w(tenant_registered tenant_beam_spawned tenant_admin_bootstrapped
                     tenant_activated tenant_provisioning_failed tenant_resumed
                     tenant_admin_invited) do
      test "#{action} passes changeset validation" do
        attrs =
          Map.merge(@valid_actor, %{
            action: unquote(action),
            timestamp: DateTime.utc_now(),
            target_type: "tenant",
            target_id: "22222222-2222-2222-2222-222222222222",
            tenant_id: "22222222-2222-2222-2222-222222222222",
            portal: "platform",
            details: %{slug: "acme"}
          })

        changeset = PlatformAuditEvent.changeset(%PlatformAuditEvent{}, attrs)
        assert changeset.valid?, "expected #{unquote(action)} to be valid, got: #{inspect(changeset.errors)}"
      end
    end

    test "rejects unknown tenant action" do
      attrs =
        Map.merge(@valid_actor, %{
          action: "tenant_bogus",
          timestamp: DateTime.utc_now()
        })

      changeset = PlatformAuditEvent.changeset(%PlatformAuditEvent{}, attrs)
      refute changeset.valid?
      assert {:action, _} = List.first(changeset.errors)
    end
  end
end
