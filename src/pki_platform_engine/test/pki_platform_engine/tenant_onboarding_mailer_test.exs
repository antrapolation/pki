defmodule PkiPlatformEngine.TenantOnboardingMailerTest do
  @moduledoc """
  Task #17: `send_admin_invitation/4` must never block the wizard
  when the mailer is misconfigured or unreachable.
  """
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.{Tenant, TenantOnboarding}

  @tenant %Tenant{
    id: "01ffffff-0000-7000-8000-000000000001",
    name: "Acme Test Co",
    slug: "acme-test",
    email: "owner@example.test",
    schema_mode: "beam",
    status: "active"
  }

  setup do
    prev = System.get_env("RESEND_API_KEY")

    on_exit(fn ->
      if prev, do: System.put_env("RESEND_API_KEY", prev), else: System.delete_env("RESEND_API_KEY")
    end)

    :ok
  end

  describe "send_admin_invitation/4" do
    test "returns {:ok, :skipped} when RESEND_API_KEY is not configured" do
      System.delete_env("RESEND_API_KEY")

      assert {:ok, :skipped} =
               TenantOnboarding.send_admin_invitation(
                 @tenant,
                 "acme-admin",
                 "temp-password-123",
                 portal_url: "http://localhost:5001/"
               )
    end

    test "never raises, even with missing opts" do
      System.delete_env("RESEND_API_KEY")

      # No portal_url / role_label — defaults must kick in.
      assert {:ok, _} =
               TenantOnboarding.send_admin_invitation(
                 @tenant,
                 "acme-admin",
                 "temp-password-123"
               )
    end
  end
end
