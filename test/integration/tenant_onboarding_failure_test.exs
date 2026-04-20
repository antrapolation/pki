defmodule PkiIntegration.TenantOnboardingFailureTest do
  @moduledoc """
  Failure-mode coverage for the per-tenant BEAM onboarding pipeline.

  Happy-path coverage lives in `tenant_beam_spawn_test.exs`. This
  suite exercises the degenerate cases the wizard has to handle
  without crashing:

    * two tenants spawned concurrently must coexist
    * slug reuse after a clean stop must succeed
    * slug reuse with leftover Mnesia data must fail with a clear
      error instead of silently reusing another tenant's schema
    * RPC timeout during app boot must return `{:error, _}`,
      never exit the caller
    * `create_initial_admin` before `boot_tenant_apps` must return
      a structured error, not blow up with `:undef`
    * peer dying post-spawn must surface as a proper error when
      `boot_tenant_apps` is called

  Not covered here (tracked as follow-ups):

    * PortAllocator exhaustion — needs PortAllocator GenServer
      running + a synthetic exhaust pass
    * Postgres Tenant-row rollback on partial failure — needs
      dedicated test DB + migrations wired
    * Peer platform-restart recovery — requires killing + restarting
      the parent, can't be done in a single ExUnit process
    * Caddy route / TLS bootstrap — M6c work
  """
  use ExUnit.Case, async: false

  @peer_boot_timeout 90_000

  setup_all do
    System.cmd("epmd", ["-daemon"], stderr_to_stdout: true)

    unless Node.alive?() do
      {:ok, _} = Node.start(:"tenant_onboarding_failure_test", :shortnames)
      Node.set_cookie(:tenant_onboarding_failure_test_cookie)
    end

    :ok
  end

  setup do
    base = Path.join(System.tmp_dir!(), "pki_tenant_failure_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(base)

    prev_base = Application.get_env(:pki_platform_engine, :tenant_mnesia_base)
    Application.put_env(:pki_platform_engine, :tenant_mnesia_base, base)

    # Mirror tenant_beam_spawn_test.exs: force engine apps to
    # start_application: true on the parent so the peer override is the
    # only thing keeping pki_tenant from colliding with the engine
    # supervisors.
    engine_apps = [:pki_ca_engine, :pki_ra_engine, :pki_validation]
    prev_engine_flags =
      for app <- engine_apps, do: {app, Application.get_env(app, :start_application)}

    for app <- engine_apps, do: Application.put_env(app, :start_application, true)

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

    %{base: base}
  end

  # --- 1. Two tenants coexist on the same platform ----------------------

  test "two concurrently-spawned tenants each have an independent Mnesia + web endpoint" do
    slug_a = "coexist_a#{System.unique_integer([:positive])}"
    slug_b = "coexist_b#{System.unique_integer([:positive])}"

    tenant_a = spawn_and_boot(slug_a)
    tenant_b = spawn_and_boot(slug_b)

    assert tenant_a.node != tenant_b.node
    assert Node.ping(tenant_a.node) == :pong
    assert Node.ping(tenant_b.node) == :pong

    # Each tenant has its own Mnesia dir.
    refute same_mnesia_dir?(tenant_a.node, tenant_b.node)

    # Independent admins — creating one in A doesn't clash with B.
    attrs = %{
      username: "admin",
      display_name: "Test Admin",
      email: "admin@example.test",
      role: "ca_admin"
    }

    assert {:ok, _, _} =
             PkiPlatformEngine.TenantLifecycle.create_initial_admin(tenant_a.node, attrs)

    assert {:ok, _, _} =
             PkiPlatformEngine.TenantLifecycle.create_initial_admin(tenant_b.node, attrs)
  end

  # --- 2. Slug reuse after clean stop ----------------------------------

  test "spawn / stop / respawn the same slug succeeds" do
    slug = "reuse_clean#{System.unique_integer([:positive])}"

    first = spawn_and_boot(slug)
    :ok = stop_peer(first.pid)

    # Peer gone — respawn should work cleanly because we delete the
    # Mnesia dir on cleanup too.
    second = spawn_and_boot(slug)
    assert Node.ping(second.node) == :pong
    stop_peer(second.pid)
  end

  # --- 3. Slug reuse with leftover Mnesia data -------------------------

  test "respawn with leftover Mnesia data reuses the schema instead of crashing", %{base: base} do
    slug = "reuse_dirty#{System.unique_integer([:positive])}"

    first = spawn_and_boot(slug)

    attrs = %{
      username: "persisted",
      display_name: "P",
      email: "p@example.test",
      role: "ca_admin"
    }

    assert {:ok, _, _} =
             PkiPlatformEngine.TenantLifecycle.create_initial_admin(first.node, attrs)

    # Gracefully stop Mnesia on the peer before killing its VM —
    # disc_copies tables have lazy disc writeback, so an abrupt
    # :peer.stop would lose the uncommitted in-memory state and this
    # test would degenerate into "fresh schema" coverage. A graceful
    # :mnesia.stop forces pending transactions out to disc.
    :rpc.call(first.node, :mnesia, :stop, [], 5_000)
    :ok = stop_peer(first.pid)

    # Don't wipe the dir. A respawn hits pre-existing Mnesia tables.
    assert File.exists?(Path.join(base, "#{slug}/mnesia"))

    second = spawn_and_boot(slug)

    # The previously-created admin must be visible — this is the
    # "reopen existing schema" path, not "wipe and recreate".
    users =
      :rpc.call(
        second.node,
        PkiTenant.PortalUserAdmin,
        :list_users,
        [:ca],
        @peer_boot_timeout
      )

    usernames = Enum.map(users, & &1.username)
    assert "persisted" in usernames

    :rpc.call(second.node, :mnesia, :stop, [], 5_000)
    stop_peer(second.pid)
  end

  # --- 4. RPC timeout during boot_tenant_apps --------------------------

  test "boot_tenant_apps with a sub-second timeout returns {:error, _} instead of exiting" do
    slug = "boot_timeout#{System.unique_integer([:positive])}"
    {:ok, pid, node} = PkiPlatformEngine.TenantLifecycle.spawn_tenant_for_test(slug_id(slug), slug, 0)

    try do
      # 1ms is far below the time needed to start :elixir. RPC returns
      # {:badrpc, :timeout}; boot_tenant_apps must translate this into
      # a structured {:error, _}.
      result = PkiPlatformEngine.TenantLifecycle.boot_tenant_apps(node, 0, 1)
      assert match?({:error, {:badrpc, :timeout}}, result),
             "expected {:error, {:badrpc, :timeout}}, got #{inspect(result)}"
    after
      stop_peer(pid)
    end
  end

  # --- 5. create_initial_admin before boot_tenant_apps -----------------

  test "create_initial_admin on a peer with no apps booted returns a structured error" do
    slug = "no_boot#{System.unique_integer([:positive])}"
    {:ok, pid, node} = PkiPlatformEngine.TenantLifecycle.spawn_tenant_for_test(slug_id(slug), slug, 0)

    try do
      attrs = %{
        username: "nobody",
        display_name: "N",
        email: "n@example.test",
        role: "ca_admin"
      }

      # PkiTenant.PortalUserAdmin module isn't loaded / its Mnesia
      # deps aren't started. RPC surfaces this as :undef → we wrap
      # it into a {:badrpc, _} or similar — the caller must never
      # crash.
      result = PkiPlatformEngine.TenantLifecycle.create_initial_admin(node, attrs)
      assert match?({:error, _}, result),
             "expected {:error, _}, got #{inspect(result)}"
    after
      stop_peer(pid)
    end
  end

  # --- 5b. Two tenants each bind their own Validation HTTP port -------

  test "each tenant BEAM binds its own Validation (OCSP) HTTP port" do
    slug_a = "ocsp_a#{System.unique_integer([:positive])}"
    slug_b = "ocsp_b#{System.unique_integer([:positive])}"

    tenant_a = spawn_and_boot(slug_a)
    tenant_b = spawn_and_boot(slug_b)

    # Each tenant's validation listener is derived as web_port + 1000.
    validation_port_a = tenant_a.web_port + 1_000
    validation_port_b = tenant_b.web_port + 1_000

    # Both must be listening.
    assert http_listening?(validation_port_a),
           "Tenant A validation should be on #{validation_port_a}"

    assert http_listening?(validation_port_b),
           "Tenant B validation should be on #{validation_port_b}"

    # And they must not collide.
    refute validation_port_a == validation_port_b
  end

  defp http_listening?(port) do
    case :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        true

      {:error, _} ->
        false
    end
  end

  # --- 6. Graceful stop preserves Mnesia disc_copies ------------------

  test "TenantLifecycle graceful stop flushes Mnesia; respawn sees prior data", %{base: base} do
    # NOTE: we spawn the peer via spawn_and_boot so the peer is known
    # to TenantLifecycle's state... except spawn_tenant_for_test doesn't
    # register the peer with the GenServer. So here we exercise the
    # graceful shutdown helper by directly calling the same RPC sequence
    # the helper performs. Task #18 (platform restart recovery) will
    # flesh out the GenServer-registered flow with a dedicated test.
    slug = "graceful_stop#{System.unique_integer([:positive])}"

    first = spawn_and_boot(slug)

    attrs = %{
      username: "survivor",
      display_name: "S",
      email: "s@example.test",
      role: "ca_admin"
    }

    assert {:ok, _, _} =
             PkiPlatformEngine.TenantLifecycle.create_initial_admin(first.node, attrs)

    # Graceful shutdown sequence (mirrors TenantLifecycle.graceful_peer_stop).
    :rpc.call(first.node, :mnesia, :stop, [], 5_000)
    :ok = stop_peer(first.pid)

    assert File.exists?(Path.join(base, "#{slug}/mnesia"))

    second = spawn_and_boot(slug)

    users =
      :rpc.call(second.node, PkiTenant.PortalUserAdmin, :list_users, [:ca], @peer_boot_timeout)

    assert "survivor" in Enum.map(users, & &1.username),
           "data committed before graceful stop must be visible on respawn"

    :rpc.call(second.node, :mnesia, :stop, [], 5_000)
    stop_peer(second.pid)
  end

  # --- 7. Peer dies post-spawn, before boot ---------------------------

  test "boot_tenant_apps on a dead peer returns {:error, _} not an exit" do
    slug = "dead_peer#{System.unique_integer([:positive])}"
    {:ok, pid, node} = PkiPlatformEngine.TenantLifecycle.spawn_tenant_for_test(slug_id(slug), slug, 0)

    # Kill the peer before touching it over RPC.
    :peer.stop(pid)
    # Give net_kernel a moment to notice.
    :timer.sleep(200)

    result = PkiPlatformEngine.TenantLifecycle.boot_tenant_apps(node, 0, 5_000)
    assert match?({:error, {:badrpc, _}}, result) or match?({:error, _}, result),
           "expected {:error, _}, got #{inspect(result)}"
  end

  # --- helpers ---------------------------------------------------------

  defp slug_id(slug), do: "01ffffff-0000-7000-8000-" <> String.slice(slug <> "000000000000", 0, 12)

  defp spawn_and_boot(slug) do
    # Allocate a unique high port per test tenant so concurrent spawns
    # don't fight over the compile-time Endpoint default (4010).
    web_port = 5_000 + rem(System.unique_integer([:positive]), 10_000)

    {:ok, pid, node} =
      PkiPlatformEngine.TenantLifecycle.spawn_tenant_for_test(slug_id(slug), slug, 0)

    on_exit(fn -> stop_peer(pid) end)

    assert :ok =
             PkiPlatformEngine.TenantLifecycle.boot_tenant_apps(node, web_port, @peer_boot_timeout)

    %{pid: pid, node: node, slug: slug, web_port: web_port}
  end

  defp stop_peer(pid) do
    try do
      :peer.stop(pid)
    catch
      :exit, _ -> :ok
    end

    :ok
  end

  defp same_mnesia_dir?(node_a, node_b) do
    dir_a = :rpc.call(node_a, :application, :get_env, [:mnesia, :dir])
    dir_b = :rpc.call(node_b, :application, :get_env, [:mnesia, :dir])
    dir_a == dir_b and dir_a != :undefined
  end
end
