defmodule PkiPlatformEngine.TenantLifecycle do
  @moduledoc """
  Spawns, stops, and monitors tenant BEAM nodes via :peer module.

  State per tenant: %{peer_pid, node, port, slug, status, monitor_ref}
  On crash, auto-restarts with 5s backoff.
  """
  use GenServer
  require Logger

  alias PkiPlatformEngine.{PortAllocator, CaddyConfigurator}

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def create_tenant(attrs) do
    GenServer.call(__MODULE__, {:create_tenant, attrs}, 30_000)
  end

  def stop_tenant(tenant_id) do
    GenServer.call(__MODULE__, {:stop_tenant, tenant_id}, 15_000)
  end

  def restart_tenant(tenant_id) do
    GenServer.call(__MODULE__, {:restart_tenant, tenant_id}, 30_000)
  end

  def list_tenants do
    GenServer.call(__MODULE__, :list_tenants)
  end

  def get_tenant(tenant_id) do
    GenServer.call(__MODULE__, {:get_tenant, tenant_id})
  end

  @doc """
  Boot the tenant application stack on a spawned node via RPC.

  A fresh peer BEAM has only OTP loaded — Elixir, every application's
  compile-time config, and the tenant apps themselves aren't present.
  The bootstrap sequence is:

    1. Start `:elixir` so the stdlib is callable on the peer.
    2. Forward the parent's application env for every app whose
       compile-time config lives in `config/config.exs` (Hammer's
       `expiry_ms` is the poster child — without it the ETS backend
       crashes at boot with `Missing required config: expiry_ms`).
    3. Inject per-tenant overrides — including the allocated web
       port so multiple tenant BEAMs don't fight over port 4010.
    4. Start `:pki_tenant_web`, which pulls in `pki_tenant`,
       `pki_ca_engine`, `pki_ra_engine`, `pki_validation`,
       `pki_mnesia` transitively and runs
       `PkiTenant.MnesiaBootstrap.init/1`.

  `web_port` is the port the tenant's Phoenix endpoint will bind on
  the peer (typically the same port `PortAllocator.allocate/1`
  returned at spawn time). Pass 0 to keep the compile-time default
  (useful for single-tenant local runs).
  """
  @spec boot_tenant_apps(node(), non_neg_integer(), timeout()) :: :ok | {:error, term()}
  def boot_tenant_apps(node, web_port \\ 0, timeout \\ 60_000) do
    with :ok <- ensure_elixir_started(node, timeout),
         :ok <- forward_compile_time_env(node, web_port, timeout),
         :ok <- ensure_app_started(node, :pki_tenant_web, timeout) do
      :ok
    end
  end

  # Apps whose compile-time config must be mirrored onto the peer so
  # their application start callbacks see the same env the parent has.
  @forwarded_apps [
    :pki_system,
    :hammer,
    :phoenix,
    :logger,
    :pki_mnesia,
    :pki_ca_engine,
    :pki_ra_engine,
    :pki_validation,
    :pki_tenant,
    :pki_tenant_web
  ]

  # Per-app env overrides applied AFTER the parent's env is forwarded.
  # On the spawned peer:
  #
  #   * pki_tenant MUST start (owns MnesiaBootstrap, AuditBridge, and
  #     the engine supervisors — PkiCaEngine.EngineSupervisor,
  #     PkiRaEngine.EngineSupervisor, PkiValidation.Supervisor).
  #   * pki_tenant_web's Phoenix endpoint MUST bind (server: true).
  #   * pki_ca_engine / pki_ra_engine / pki_validation MUST NOT start
  #     their own supervisors — pki_tenant owns them. The parent's dev
  #     env has start_application: true for these (default), which if
  #     forwarded would race pki_tenant for the same named GenServers,
  #     surfacing as {:already_started, _}. Force them off here.
  @peer_env_overrides %{
    pki_tenant: [start_application: true],
    pki_ca_engine: [start_application: false],
    pki_ra_engine: [start_application: false],
    pki_validation: [start_application: false]
    # :pki_tenant_web is added dynamically in apply_peer_overrides/3
    # because it needs the per-tenant web port.
  }

  defp forward_compile_time_env(node, web_port, timeout) do
    with :ok <- push_parent_env(node, timeout) do
      apply_peer_overrides(node, web_port, timeout)
    end
  end

  defp push_parent_env(node, timeout) do
    Enum.reduce_while(@forwarded_apps, :ok, fn app, :ok ->
      case push_env(node, app, timeout) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp push_env(node, app, timeout) do
    env_pairs = Application.get_all_env(app)

    Enum.reduce_while(env_pairs, :ok, fn {key, value}, :ok ->
      case :rpc.call(node, :application, :set_env, [app, key, value], timeout) do
        :ok ->
          {:cont, :ok}

        {:badrpc, reason} ->
          {:halt, {:error, {:badrpc, app, key, reason}}}

        other ->
          {:halt, {:error, {:set_env_failed, app, key, other}}}
      end
    end)
  end

  defp apply_peer_overrides(node, web_port, timeout) do
    overrides = Map.put(@peer_env_overrides, :pki_tenant_web, tenant_web_overrides(web_port))

    Enum.reduce_while(overrides, :ok, fn {app, app_overrides}, :ok ->
      Enum.reduce_while(app_overrides, :ok, fn override, :ok ->
        {key, value} = normalize_override(override)

        case :rpc.call(node, :application, :set_env, [app, key, value], timeout) do
          :ok ->
            {:cont, :ok}

          {:badrpc, reason} ->
            {:halt, {:error, {:override_badrpc, app, key, reason}}}

          other ->
            {:halt, {:error, {:override_failed, app, key, other}}}
        end
      end)
      |> case do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  # tenant_web overrides include the per-tenant HTTP port so two
  # tenant BEAMs on the same host don't fight over port 4010. `0`
  # means "keep the compile-time default" (single-tenant local
  # runs).
  defp tenant_web_overrides(0),
    do: [{{PkiTenantWeb.Endpoint, :server}, true}]

  defp tenant_web_overrides(web_port) when is_integer(web_port) do
    [
      {{PkiTenantWeb.Endpoint, :server}, true},
      {{PkiTenantWeb.Endpoint, :http}, [port: web_port]}
    ]
  end

  # The `{{Module, :key}, value}` form mutates a nested keyword list
  # (Phoenix's endpoint config uses this shape).
  defp normalize_override({{mod, subkey}, value}) do
    existing_list =
      case Application.get_env(:pki_tenant_web, mod, []) do
        list when is_list(list) -> list
        _ -> []
      end

    {mod, Keyword.put(existing_list, subkey, value)}
  end

  defp normalize_override({key, value}), do: {key, value}

  defp ensure_elixir_started(node, timeout) do
    case :rpc.call(node, :application, :ensure_all_started, [:elixir], timeout) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:elixir_start_failed, reason}}
      {:badrpc, reason} -> {:error, {:badrpc, reason}}
    end
  end

  defp ensure_app_started(node, app, timeout) do
    case :rpc.call(node, :application, :ensure_all_started, [app], timeout) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:app_start_failed, app, reason}}
      {:badrpc, reason} -> {:error, {:badrpc, reason}}
    end
  end

  @doc """
  Create the initial ca_admin user on a spawned tenant node via RPC.

  Returns `{:ok, user, plaintext_password}` so the operator can show
  the password once in the UI (email delivery is a separate concern).
  """
  @spec create_initial_admin(node(), map(), timeout()) ::
          {:ok, map(), String.t()} | {:error, term()}
  def create_initial_admin(node, attrs, timeout \\ 15_000) do
    case :rpc.call(node, PkiTenant.PortalUserAdmin, :create_user, [attrs], timeout) do
      {:ok, user, plaintext} -> {:ok, user, plaintext}
      {:error, reason} -> {:error, reason}
      {:badrpc, reason} -> {:error, {:badrpc, reason}}
    end
  end

  @max_restart_attempts 5
  @base_backoff_ms 5_000
  @max_backoff_ms 300_000

  @impl true
  def init(_opts) do
    {:ok, %{tenants: %{}}}
  end

  @impl true
  def handle_call({:create_tenant, attrs}, _from, state) do
    tenant_id = attrs.id || Uniq.UUID.uuid7()
    slug = attrs.slug

    case PortAllocator.allocate(tenant_id) do
      {:ok, port} ->
        case spawn_tenant(tenant_id, slug, port) do
          {:ok, peer_pid, node_name} ->
            ref = Process.monitor(peer_pid)

            tenant_info = %{
              peer_pid: peer_pid,
              node: node_name,
              port: port,
              slug: slug,
              status: :starting,
              monitor_ref: ref,
              restart_count: 0
            }

            new_state = %{state | tenants: Map.put(state.tenants, tenant_id, tenant_info)}
            notify_replica(:tenant_started, %{tenant_id: tenant_id, slug: slug, node: node_name})
            {:reply, {:ok, %{tenant_id: tenant_id, port: port, node: node_name}}, new_state}

          {:error, reason} ->
            PortAllocator.release(tenant_id)
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:stop_tenant, tenant_id}, _from, state) do
    case Map.get(state.tenants, tenant_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      info ->
        :peer.stop(info.peer_pid)
        PortAllocator.release(tenant_id)
        CaddyConfigurator.remove_route(info.slug)
        new_tenants = Map.delete(state.tenants, tenant_id)
        notify_replica(:tenant_stopped, %{tenant_id: tenant_id})
        {:reply, :ok, %{state | tenants: new_tenants}}
    end
  end

  @impl true
  def handle_call({:restart_tenant, tenant_id}, _from, state) do
    case Map.get(state.tenants, tenant_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      info ->
        # Save the port before stopping so we can reuse it (do NOT release from PortAllocator)
        saved_port = info.port
        saved_slug = info.slug

        :peer.stop(info.peer_pid)

        # Remove old monitor ref from state but keep port in PortAllocator
        state_without_tenant = %{state | tenants: Map.delete(state.tenants, tenant_id)}

        # Respawn with the same port
        case spawn_tenant(tenant_id, saved_slug, saved_port) do
          {:ok, peer_pid, node_name} ->
            ref = Process.monitor(peer_pid)

            tenant_info = %{
              peer_pid: peer_pid,
              node: node_name,
              port: saved_port,
              slug: saved_slug,
              status: :starting,
              monitor_ref: ref,
              restart_count: 0
            }

            new_state = %{state_without_tenant | tenants: Map.put(state_without_tenant.tenants, tenant_id, tenant_info)}
            notify_replica(:tenant_started, %{tenant_id: tenant_id, slug: saved_slug, node: node_name})
            {:reply, {:ok, %{tenant_id: tenant_id, port: saved_port, node: node_name}}, new_state}

          {:error, reason} ->
            {:reply, {:error, reason}, state_without_tenant}
        end
    end
  end

  @impl true
  def handle_call(:list_tenants, _from, state) do
    list =
      Enum.map(state.tenants, fn {id, info} ->
        %{id: id, slug: info.slug, port: info.port, status: info.status, node: info.node}
      end)

    {:reply, list, state}
  end

  @impl true
  def handle_call({:get_tenant, tenant_id}, _from, state) do
    case Map.get(state.tenants, tenant_id) do
      nil -> {:reply, {:error, :not_found}, state}
      info -> {:reply, {:ok, info}, state}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    case Enum.find(state.tenants, fn {_id, info} -> info.peer_pid == pid end) do
      {tenant_id, info} ->
        Logger.error(
          "[tenant_lifecycle] Tenant #{tenant_id} (#{info.slug}) crashed: #{inspect(reason)}"
        )

        restart_count = Map.get(info, :restart_count, 0)

        if restart_count >= @max_restart_attempts do
          Logger.error(
            "[tenant_lifecycle] Tenant #{tenant_id} exceeded #{@max_restart_attempts} restart attempts — marking as failed"
          )
          new_info = %{info | status: :failed}
          {:noreply, %{state | tenants: Map.put(state.tenants, tenant_id, new_info)}}
        else
          backoff = min(@base_backoff_ms * trunc(:math.pow(2, restart_count)), @max_backoff_ms)
          Logger.info(
            "[tenant_lifecycle] Scheduling auto-restart for #{tenant_id} in #{backoff}ms (attempt #{restart_count + 1}/#{@max_restart_attempts})"
          )
          Process.send_after(self(), {:auto_restart, tenant_id, info.slug, restart_count + 1}, backoff)
          new_info = %{info | status: :crashed, restart_count: restart_count}
          {:noreply, %{state | tenants: Map.put(state.tenants, tenant_id, new_info)}}
        end

      nil ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:auto_restart, tenant_id, slug, restart_count}, state) do
    Logger.info("[tenant_lifecycle] Auto-restarting tenant #{tenant_id} (attempt #{restart_count})")

    case Map.get(state.tenants, tenant_id) do
      %{status: :crashed} = info ->
        case PortAllocator.get_port(tenant_id) do
          nil ->
            Logger.error("[tenant_lifecycle] Cannot restart #{tenant_id}: port not found")
            {:noreply, put_in(state, [:tenants, tenant_id, :status], :failed)}

          port ->
            case spawn_tenant(tenant_id, slug, port) do
              {:ok, peer_pid, node_name} ->
                ref = Process.monitor(peer_pid)

                new_info = %{
                  peer_pid: peer_pid,
                  node: node_name,
                  port: port,
                  slug: slug,
                  status: :starting,
                  monitor_ref: ref,
                  restart_count: 0
                }

                notify_replica(:tenant_started, %{tenant_id: tenant_id, slug: slug, node: node_name})
                {:noreply, %{state | tenants: Map.put(state.tenants, tenant_id, new_info)}}

              {:error, reason} ->
                Logger.error(
                  "[tenant_lifecycle] Auto-restart failed for #{tenant_id}: #{inspect(reason)}"
                )

                if restart_count >= @max_restart_attempts do
                  Logger.error(
                    "[tenant_lifecycle] Tenant #{tenant_id} exceeded #{@max_restart_attempts} restart attempts — marking as failed"
                  )
                  {:noreply, put_in(state, [:tenants, tenant_id, :status], :failed)}
                else
                  backoff = min(@base_backoff_ms * trunc(:math.pow(2, restart_count)), @max_backoff_ms)
                  Process.send_after(self(), {:auto_restart, tenant_id, slug, restart_count + 1}, backoff)
                  new_info = %{info | restart_count: restart_count}
                  {:noreply, %{state | tenants: Map.put(state.tenants, tenant_id, new_info)}}
                end
            end
        end

      _ ->
        {:noreply, state}
    end
  end

  defp notify_replica(event, payload) do
    case Application.get_env(:pki_platform_engine, :replica_node) do
      nil -> :ok  # no replica configured
      replica_node ->
        GenServer.cast({PkiReplica.TenantReplicaSupervisor, replica_node}, {event, payload})
    end
  rescue
    _ -> :ok  # replica unreachable, non-critical
  end

  @doc false
  # Exposed for integration tests so they exercise the exact same
  # args-building + :peer.start/1 path the GenServer uses. NOT part of
  # the public API — call `create_tenant/1` from product code.
  def spawn_tenant_for_test(tenant_id, slug, port) do
    spawn_tenant(tenant_id, slug, port)
  end

  defp spawn_tenant(tenant_id, slug, port) do
    platform_node = Atom.to_string(node())
    cookie = Atom.to_string(Node.get_cookie())
    mnesia_dir =
      Application.get_env(:pki_platform_engine, :tenant_mnesia_base, "/var/lib/pki/tenants")
      |> Path.join("#{slug}/mnesia")

    # Match the parent's distribution naming style — Erlang refuses to
    # mix short names (-sname) and long names (-name) in the same cluster.
    {name_flag, node_name} = peer_name(slug)

    # :peer inherits some but not all code paths from the parent. In
    # particular Elixir's own ebin (added dynamically by the `elixir`
    # launcher) is missing on the peer, so :application.ensure_all_started(:elixir)
    # fails with "no such file or directory elixir.app". Fix by
    # explicitly forwarding every entry of the parent's code path via -pa.
    #
    # Use Enum.flat_map, NOT Enum.map + List.flatten — charlists ARE lists
    # of integers, so List.flatten would dissolve them into raw ints and
    # :peer.start would reject with {:invalid_arg, 45} (the '-' char).
    code_path_args = Enum.flat_map(:code.get_path(), fn path -> [~c"-pa", path] end)

    args =
      [
        ~c"-setcookie",
        String.to_charlist(cookie),
        name_flag,
        Atom.to_charlist(node_name)
      ] ++ code_path_args

    env = [
      {~c"TENANT_ID", String.to_charlist(tenant_id)},
      {~c"TENANT_SLUG", String.to_charlist(slug)},
      {~c"TENANT_PORT", String.to_charlist(Integer.to_string(port))},
      {~c"MNESIA_DIR", String.to_charlist(mnesia_dir)},
      {~c"PLATFORM_NODE", String.to_charlist(platform_node)},
      {~c"RELEASE_COOKIE", String.to_charlist(cookie)}
    ]

    # :peer.start/1 (not start_link) — if the spawned BEAM fails to boot, we
    # get back {:error, reason} instead of killing the TenantLifecycle
    # GenServer that called us. Monitor is established by the caller.
    try do
      case :peer.start(%{
             name: node_name,
             args: args,
             env: env,
             connection: :standard_io
           }) do
        {:ok, pid, actual_node} -> {:ok, pid, actual_node}
        {:ok, pid} -> {:ok, pid, node_name}
        {:error, reason} -> {:error, reason}
      end
    rescue
      e -> {:error, {:spawn_failed, Exception.message(e)}}
    catch
      :exit, reason -> {:error, {:peer_boot_failed, reason}}
    end
  end

  # Return {name_flag, node_name} matching the parent's distribution style.
  # Parent uses -sname if `node()` has no `@` or the host part is a short
  # hostname; -name if the host part is an FQDN / IP. Mixing styles makes
  # net_kernel on the peer fail with :nodistribution.
  defp peer_name(slug) do
    parent = node() |> Atom.to_string()
    short_name = "pki_tenant_#{slug}"

    case parent do
      "nonode@nohost" ->
        # Parent isn't distributed — fall back to long names on a loopback
        # host so peer's -name still registers cleanly.
        {~c"-name", :"#{short_name}@127.0.0.1"}

      _ ->
        [_, host] = String.split(parent, "@", parts: 2)

        if String.contains?(host, ".") do
          {~c"-name", :"#{short_name}@#{host}"}
        else
          {~c"-sname", :"#{short_name}@#{host}"}
        end
    end
  end
end
