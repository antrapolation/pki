defmodule PkiIntegration.TenantSupervisorRespawnTest do
  @moduledoc """
  Coverage for task #18: platform restart must respawn active BEAM tenants.

  `PkiPlatformEngine.TenantSupervisor.boot_active_tenants/0` runs on
  platform boot, enumerating active rows and calling `start_tenant/2`
  for each. For BEAM-mode rows, this delegates to
  `PkiPlatformEngine.TenantLifecycle.create_tenant/1`.

  We can't easily kill-and-restart the parent BEAM in a single ExUnit
  run, so the behaviour we verify here is the core invariant:

    * `start_tenant(%{schema_mode: "beam", ...})` uses TenantLifecycle
      to spawn a peer (happy path), and
    * calling it a second time for a tenant that's already tracked
      by TenantLifecycle short-circuits to the existing peer instead
      of double-spawning.

  Stopping BEAM tenants through the supervisor must also route through
  TenantLifecycle (not the legacy TenantProcess path).
  """
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.{PortAllocator, TenantLifecycle, TenantSupervisor}

  setup_all do
    System.cmd("epmd", ["-daemon"], stderr_to_stdout: true)

    unless Node.alive?() do
      {:ok, _} = Node.start(:"tenant_supervisor_respawn_test", :shortnames)
      Node.set_cookie(:tenant_supervisor_respawn_test_cookie)
    end

    base = Path.join(System.tmp_dir!(), "pki_tenant_respawn_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(base)

    prev_base = Application.get_env(:pki_platform_engine, :tenant_mnesia_base)
    Application.put_env(:pki_platform_engine, :tenant_mnesia_base, base)

    engine_apps = [:pki_ca_engine, :pki_ra_engine, :pki_validation]
    prev_engine_flags =
      for app <- engine_apps, do: {app, Application.get_env(app, :start_application)}

    for app <- engine_apps, do: Application.put_env(app, :start_application, true)

    # Start PortAllocator + TenantLifecycle once for the whole suite.
    # If the same process is torn down and re-created per test the OS
    # keeps the freshly-allocated ports in TIME_WAIT for ~60s — fine
    # for production but fatal for a test that wants to re-bind 5001
    # a second time.
    #
    # PortAllocator is PG-free (persist: false) to avoid needing a
    # real test database. We also pick a random starting port so
    # parallel CI runs and successive rebuilds don't step on each
    # other's TIME_WAIT ports.
    base_port = 5500 + :rand.uniform(100) * 10
    port_range = base_port..(base_port + 9)

    allocator_pid = ensure_started(PortAllocator, persist: false, port_range: port_range)
    lifecycle_pid = ensure_started(TenantLifecycle, [])

    on_exit(fn ->
      TenantLifecycle.list_tenants()
      |> Enum.each(fn info -> _ = TenantLifecycle.stop_tenant(info.id) end)

      if Process.alive?(lifecycle_pid), do: GenServer.stop(lifecycle_pid)
      if Process.alive?(allocator_pid), do: GenServer.stop(allocator_pid)

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

  # Per-test cleanup. setup_all keeps TenantLifecycle + PortAllocator
  # alive across tests (OS TIME_WAIT on validation ports forces this),
  # so each test is responsible for tearing down the peers it spawned.
  setup do
    tenant_ids_before =
      TenantLifecycle.list_tenants() |> MapSet.new(& &1.id)

    on_exit(fn ->
      TenantLifecycle.list_tenants()
      |> Enum.reject(&MapSet.member?(tenant_ids_before, &1.id))
      |> Enum.each(fn info -> _ = TenantLifecycle.stop_tenant(info.id) end)
    end)

    :ok
  end

  test "start_tenant/2 with schema_mode: \"beam\" spawns a peer via TenantLifecycle" do
    tenant = build_tenant("respawn_fresh")

    assert {:ok, info} = TenantSupervisor.start_tenant(tenant)
    assert is_atom(info.node)
    assert Node.ping(info.node) == :pong

    # TenantLifecycle is now the source of truth for this tenant's peer.
    assert {:ok, live} = TenantLifecycle.get_tenant(tenant.id)
    assert live.node == info.node
  end

  test "start_tenant/2 short-circuits when a peer is already running" do
    tenant = build_tenant("respawn_idempotent")

    assert {:ok, first} = TenantSupervisor.start_tenant(tenant)
    first_node = first.node

    # Simulate platform restart picking up the same tenant a second
    # time. Must reuse the existing peer, not spin up a second one.
    assert {:ok, second} = TenantSupervisor.start_tenant(tenant)
    assert second.node == first_node

    # Only one entry in lifecycle state for this tenant.
    matching =
      TenantLifecycle.list_tenants()
      |> Enum.filter(&(&1.id == tenant.id))

    assert length(matching) == 1
  end

  test "stop_tenant/2 routes BEAM tenants through TenantLifecycle" do
    tenant = build_tenant("respawn_stop")

    assert {:ok, info} = TenantSupervisor.start_tenant(tenant)
    assert Node.ping(info.node) == :pong

    :ok = TenantSupervisor.stop_tenant(tenant.id)

    # Peer must be gone from TenantLifecycle state.
    assert {:error, :not_found} = TenantLifecycle.get_tenant(tenant.id)
  end

  # --- helpers ----------------------------------------------------------

  defp build_tenant(prefix) do
    slug = "#{prefix}#{System.unique_integer([:positive])}"

    %{
      id: "01ffffff-0000-7000-8000-" <> String.slice(slug <> "000000000000", 0, 12),
      name: "Test " <> slug,
      slug: slug,
      schema_mode: "beam",
      status: "active"
    }
  end

  defp ensure_started(module, opts) do
    case Process.whereis(module) do
      nil ->
        {:ok, pid} = module.start_link(opts)
        pid

      pid ->
        pid
    end
  end

end
