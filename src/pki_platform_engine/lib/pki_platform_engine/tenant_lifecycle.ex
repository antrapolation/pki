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

  After `:peer.start_link` returns, the child BEAM has runtime but no
  tenant apps running. In dev this call loads `pki_tenant_web` (which
  pulls in `pki_tenant`, `pki_ca_engine`, `pki_ra_engine`,
  `pki_validation`, `pki_mnesia` transitively) and waits for the
  web endpoint to respond.

  Shared code paths mean the spawned node sees the parent's beam files;
  the actual `Mnesia` schema is created in `PkiTenant.MnesiaBootstrap.init/1`
  at app start, using the `MNESIA_DIR` env var set in `spawn_tenant/3`.
  """
  @spec boot_tenant_apps(node(), timeout()) :: :ok | {:error, term()}
  def boot_tenant_apps(node, timeout \\ 60_000) do
    case :rpc.call(node, Application, :ensure_all_started, [:pki_tenant_web], timeout) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:app_start_failed, reason}}
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

  defp spawn_tenant(tenant_id, slug, port) do
    platform_node = Atom.to_string(node())
    cookie = Atom.to_string(Node.get_cookie())
    mnesia_dir = "/var/lib/pki/tenants/#{slug}/mnesia"

    node_name = :"pki_tenant_#{slug}@127.0.0.1"

    args = [
      ~c"-setcookie",
      String.to_charlist(cookie),
      ~c"-name",
      Atom.to_charlist(node_name)
    ]

    env = [
      {~c"TENANT_ID", String.to_charlist(tenant_id)},
      {~c"TENANT_SLUG", String.to_charlist(slug)},
      {~c"TENANT_PORT", String.to_charlist(Integer.to_string(port))},
      {~c"MNESIA_DIR", String.to_charlist(mnesia_dir)},
      {~c"PLATFORM_NODE", String.to_charlist(platform_node)},
      {~c"RELEASE_COOKIE", String.to_charlist(cookie)}
    ]

    case :peer.start_link(%{
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
  end
end
