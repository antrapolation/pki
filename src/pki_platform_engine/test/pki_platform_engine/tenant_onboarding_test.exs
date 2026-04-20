defmodule PkiPlatformEngine.TenantOnboardingTest do
  @moduledoc """
  Light-touch tests for the onboarding orchestration.

  `spawn_beam/1` and `bootstrap_first_admin/2` talk to `:peer` and
  to a remote node over RPC, so they're exercised end-to-end in the
  live platform portal smoke test. Here we just cover the parts
  that are pure/unit-testable.
  """
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.TenantOnboarding

  describe "module surface" do
    test "exports the four-step onboarding API with the expected arities" do
      exports = TenantOnboarding.__info__(:functions)

      assert {:register_tenant, 3} in exports
      assert {:spawn_beam, 1} in exports
      assert {:bootstrap_first_admin, 2} in exports
      assert {:activate_tenant, 1} in exports
    end

    test "no longer exposes the legacy schema-mode helpers" do
      exports = TenantOnboarding.__info__(:functions)

      refute {:create_database, 3} in exports
      refute {:create_database, 4} in exports
      refute {:activate, 1} in exports
      refute {:create_instances, 1} in exports
      refute {:create_tenant_admin, 1} in exports
    end

    test "exposes failure recovery helpers" do
      exports = TenantOnboarding.__info__(:functions)

      assert {:mark_failed, 2} in exports
      assert {:resume_provisioning, 1} in exports
    end
  end
end
