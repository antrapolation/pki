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
              monitor_ref: ref
            }

            new_state = %{state | tenants: Map.put(state.tenants, tenant_id, tenant_info)}
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
        {:reply, :ok, %{state | tenants: new_tenants}}
    end
  end

  @impl true
  def handle_call({:restart_tenant, tenant_id}, from, state) do
    case Map.get(state.tenants, tenant_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      info ->
        :peer.stop(info.peer_pid)
        # Re-spawn with same port and slug
        handle_call(
          {:create_tenant, %{id: tenant_id, slug: info.slug}},
          from,
          %{state | tenants: Map.delete(state.tenants, tenant_id)}
        )
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

        # Auto-restart with backoff
        Process.send_after(self(), {:auto_restart, tenant_id, info.slug}, 5_000)
        new_info = %{info | status: :crashed}
        {:noreply, %{state | tenants: Map.put(state.tenants, tenant_id, new_info)}}

      nil ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:auto_restart, tenant_id, slug}, state) do
    Logger.info("[tenant_lifecycle] Auto-restarting tenant #{tenant_id}")

    case Map.get(state.tenants, tenant_id) do
      %{status: :crashed} ->
        port = PortAllocator.get_port(tenant_id) || 0

        case spawn_tenant(tenant_id, slug, port) do
          {:ok, peer_pid, node_name} ->
            ref = Process.monitor(peer_pid)

            new_info = %{
              peer_pid: peer_pid,
              node: node_name,
              port: port,
              slug: slug,
              status: :starting,
              monitor_ref: ref
            }

            {:noreply, %{state | tenants: Map.put(state.tenants, tenant_id, new_info)}}

          {:error, reason} ->
            Logger.error(
              "[tenant_lifecycle] Auto-restart failed for #{tenant_id}: #{inspect(reason)}"
            )

            {:noreply, state}
        end

      _ ->
        {:noreply, state}
    end
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
