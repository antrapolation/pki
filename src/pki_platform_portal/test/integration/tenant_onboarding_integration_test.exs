defmodule PkiPlatformPortal.TenantOnboardingIntegrationTest do
  @moduledoc """
  Task #21: end-to-end coverage combining the Postgres `tenants`
  row lifecycle with the per-tenant BEAM spawn.

  The earlier integration suites in `/test/integration/` deliberately
  skipped Postgres (no PlatformRepo wired there). The existing
  `provisioner_test.exs` in `pki_platform_engine` hits Postgres but
  stays inside the schema-mode path — it never spawns a peer because
  `pki_platform_engine` doesn't carry `pki_tenant_web` on its
  code path.

  `pki_platform_portal` has both:

    * PlatformRepo (via `pki_platform_engine` dep), sandboxed against
      the `pki_platform_test` database, and
    * the tenant-side apps (`pki_tenant`, `pki_tenant_web`,
      `pki_mnesia`) on the code path so spawned peers can boot.

  The test exercises the full four-step wizard through
  `TenantOnboarding`, plus the recovery helpers from task #13
  (`mark_failed/2`, `resume_provisioning/1`), and verifies that
  row-level writes and port allocations land in Postgres as
  expected.

  The peer never touches `PlatformRepo` — it has its own Mnesia —
  so the sandbox covers only the parent's writes.
  """
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias PkiPlatformEngine.{PlatformRepo, PortAllocator, Tenant, TenantLifecycle, TenantOnboarding}

  @peer_boot_timeout 90_000

  setup_all do
    System.cmd("epmd", ["-daemon"], stderr_to_stdout: true)

    unless Node.alive?() do
      {:ok, _} = Node.start(:"tenant_onboarding_integration_test", :shortnames)
      Node.set_cookie(:tenant_onboarding_integration_test_cookie)
    end

    # Force engine apps start_application: true so the peer-side
    # override is the only thing preventing engine supervisors from
    # racing pki_tenant's. Matches tenant_beam_spawn_test.exs.
    engine_apps = [:pki_ca_engine, :pki_ra_engine, :pki_validation]
    prev_engine_flags =
      for app <- engine_apps, do: {app, Application.get_env(app, :start_application)}

    for app <- engine_apps, do: Application.put_env(app, :start_application, true)

    base = Path.join(System.tmp_dir!(), "pki_tenant_integration_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(base)

    prev_base = Application.get_env(:pki_platform_engine, :tenant_mnesia_base)
    Application.put_env(:pki_platform_engine, :tenant_mnesia_base, base)

    on_exit(fn ->
      if prev_base,
        do: Application.put_env(:pki_platform_engine, :tenant_mnesia_base, prev_base),
        else: Application.delete_env(:pki_platform_engine, :tenant_mnesia_base)

      for {app, prev} <- prev_engine_flags do
        if is_nil(prev),
          do: Application.delete_env(app, :start_application),
          else: Application.put_env(app, :start_application, prev)
      end

      File.rm_rf!(base)
    end)

    :ok
  end

  setup do
    :ok = Sandbox.checkout(PlatformRepo)
    Sandbox.mode(PlatformRepo, {:shared, self()})

    # Allow the always-running TenantLifecycle + PortAllocator
    # GenServers (started by the pki_platform_engine app supervisor)
    # to see the sandbox connection.
    for name <- [PortAllocator, TenantLifecycle] do
      if pid = Process.whereis(name), do: Sandbox.allow(PlatformRepo, self(), pid)
    end

    on_exit(fn ->
      try do
        TenantLifecycle.list_tenants()
        |> Enum.each(fn info -> _ = TenantLifecycle.stop_tenant(info.id) end)
      rescue
        _ -> :ok
      end
    end)

    :ok
  end

  describe "happy path: register → spawn → admin → activate" do
    test "writes survive across the full wizard sequence" do
      suffix = "#{System.unique_integer([:positive])}"
      slug = "onb#{suffix}"
      email = "owner-#{suffix}@example.test"

      assert {:ok, %Tenant{} = tenant} =
               TenantOnboarding.register_tenant("Integration Co #{suffix}", slug, email)

      assert tenant.status == "provisioning"
      assert tenant.schema_mode == "beam"

      reloaded = PlatformRepo.get(Tenant, tenant.id)
      assert reloaded.slug == slug
      assert reloaded.email == email

      assert {:ok, info} = TenantOnboarding.spawn_beam(tenant)
      assert is_atom(info.node)
      assert is_integer(info.port)
      assert Node.ping(info.node) == :pong

      assert PortAllocator.get_port(tenant.id) == info.port

      assert {:ok, user, password} =
               TenantOnboarding.bootstrap_first_admin(tenant, info.node)

      assert user.username == "#{slug}-admin"
      assert is_binary(password) and byte_size(password) >= 16

      assert {:ok, %Tenant{status: "active"}} = TenantOnboarding.activate_tenant(tenant.id)
      assert PlatformRepo.get(Tenant, tenant.id).status == "active"
    end
  end

  describe "failure recovery" do
    test "mark_failed/2 records the reason and flips the row to failed" do
      suffix = "#{System.unique_integer([:positive])}"
      slug = "fail#{suffix}"

      {:ok, tenant} =
        TenantOnboarding.register_tenant(
          "Fail Co #{suffix}",
          slug,
          "fail-#{suffix}@example.test"
        )

      reason = {:spawn_failed, :simulated}

      assert {:ok, %Tenant{status: "failed", metadata: meta}} =
               TenantOnboarding.mark_failed(tenant.id, reason)

      assert meta["failure"]["step"] == "spawn_failed"
      assert meta["failure"]["detail"] =~ "simulated"
      assert is_binary(meta["failure"]["at"])
    end

    test "resume_provisioning/1 picks a failed row back up through to active" do
      suffix = "#{System.unique_integer([:positive])}"
      slug = "resume#{suffix}"

      {:ok, tenant} =
        TenantOnboarding.register_tenant(
          "Resume Co #{suffix}",
          slug,
          "resume-#{suffix}@example.test"
        )

      {:ok, _} = TenantOnboarding.mark_failed(tenant.id, {:admin_failed, :simulated})

      assert {:ok, result} = TenantOnboarding.resume_provisioning(tenant.id)
      assert result.tenant.status == "active"
      assert is_binary(result.admin.password)
      assert Node.ping(result.beam.node) == :pong

      assert PlatformRepo.get(Tenant, tenant.id).status == "active"
      assert PortAllocator.get_port(tenant.id) == result.beam.port
    end
  end

end
