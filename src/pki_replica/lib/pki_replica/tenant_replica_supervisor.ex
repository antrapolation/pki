defmodule PkiReplica.TenantReplicaSupervisor do
  @moduledoc """
  Manages replica tenant BEAM nodes on the replica server.

  On boot:
  1. Queries the primary platform node for running tenants via :erpc
  2. Spawns a replica tenant node for each via :peer with REPLICA_MODE=true
  3. Listens for push notifications from TenantLifecycle (tenant_started / tenant_stopped)
  4. Polls the primary every 30 seconds as a backup for missed notifications

  Each replica tenant runs a minimal supervision tree (MnesiaBootstrap in replica
  mode + AuditBridge) that joins the primary tenant's Mnesia cluster.

  Accepts a `:spawn_fn` option for testing — a 2-arity function receiving
  `(slug, primary_tenant_node)` and returning `{:ok, info_map}` or `{:error, reason}`.

  Accepts `spawn_replicas: false` to skip actually spawning nodes (useful in tests).
  """
  use GenServer

  require Logger

  @default_poll_interval_ms 30_000

  # -- Public API --

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Returns map of `slug => %{node: ..., peer_pid: ..., slug: ..., status: :running}` for all managed replicas."
  def list_replicas(server \\ __MODULE__) do
    GenServer.call(server, :list_replicas)
  end

  @doc "Returns replica info map for a single tenant slug, or nil if not found."
  def get_replica(slug, server \\ __MODULE__) do
    GenServer.call(server, {:get_replica, slug})
  end

  @doc """
  Promote a single tenant on this replica — called by FailoverManager during failover.

  Stops the replica peer node, then restarts it without REPLICA_MODE so it becomes
  a full primary. Returns `:ok` or `{:error, reason}`.
  """
  def promote_tenant(slug, server \\ __MODULE__) do
    GenServer.call(server, {:promote_tenant, slug}, 60_000)
  end

  @doc "Demote a promoted tenant back to replica mode. Used when primary recovers."
  def demote_tenant(slug, server \\ __MODULE__) do
    GenServer.call(server, {:demote_tenant, slug}, 30_000)
  end

  # -- GenServer callbacks --

  @impl true
  def init(opts) do
    primary_node = Keyword.fetch!(opts, :primary_node)
    poll_interval_ms = Keyword.get(opts, :poll_interval_ms, @default_poll_interval_ms)
    spawn_replicas = Keyword.get(opts, :spawn_replicas, true)
    spawn_fn = Keyword.get(opts, :spawn_fn, &default_spawn/2)

    state = %{
      primary_node: primary_node,
      poll_interval_ms: poll_interval_ms,
      spawn_replicas: spawn_replicas,
      spawn_fn: spawn_fn,
      # tenant_id => %{slug, node} — tenants known on the primary
      known_tenants: %{},
      # slug => %{node, peer_pid, slug, status} — locally running replicas
      replicas: %{}
    }

    # Kick off initial sync asynchronously so boot doesn't block on an unreachable primary
    send(self(), :sync_tenants)
    schedule_poll(poll_interval_ms)

    {:ok, state}
  end

  @impl true
  def handle_call(:list_replicas, _from, state) do
    {:reply, state.replicas, state}
  end

  @impl true
  def handle_call({:get_replica, slug}, _from, state) do
    {:reply, Map.get(state.replicas, slug), state}
  end

  @impl true
  def handle_call({:promote_tenant, slug}, _from, state) do
    case Map.get(state.replicas, slug) do
      nil ->
        {:reply, {:error, :not_found}, state}

      info ->
        # Stop the replica peer node and restart without REPLICA_MODE.
        # The simplest approach: stop the old peer then respawn without REPLICA_MODE env var.
        :ok = stop_peer(info)

        primary_tenant_node = Map.get(info, :primary_tenant_node)

        case respawn_as_primary(slug, primary_tenant_node) do
          {:ok, new_info} ->
            new_replicas = Map.put(state.replicas, slug, Map.put(new_info, :status, :promoted))
            {:reply, :ok, %{state | replicas: new_replicas}}

          {:error, reason} ->
            new_replicas = Map.delete(state.replicas, slug)
            {:reply, {:error, reason}, %{state | replicas: new_replicas}}
        end
    end
  end

  @impl true
  def handle_call({:demote_tenant, slug}, _from, state) do
    case Map.get(state.replicas, slug) do
      nil ->
        {:reply, {:error, :not_found}, state}

      info ->
        replica_node = info.node

        # Stop engines + web that were started on promotion
        try do
          :erpc.call(replica_node, fn ->
            Application.stop(:pki_tenant_web)
            Application.stop(:pki_validation)
            Application.stop(:pki_ra_engine)
            Application.stop(:pki_ca_engine)
          end, 15_000)
        rescue
          _ -> :ok
        catch
          :exit, _ -> :ok
        end

        # Demote Mnesia tables back to ram_copies on the replica node
        try do
          :erpc.call(
            replica_node,
            PkiMnesia.Schema,
            :demote_to_replica,
            [state.primary_node],
            15_000
          )
        rescue
          _ -> :ok
        catch
          :exit, _ -> :ok
        end

        # Release any HTTP port that was allocated on promotion
        try do
          PkiReplica.PortAllocator.release(slug)
        rescue
          _ -> :ok
        catch
          :exit, _ -> :ok
        end

        {:reply, :ok, state}
    end
  end

  # -- Push notifications from TenantLifecycle --

  @impl true
  def handle_cast({:tenant_started, %{tenant_id: id, slug: slug, node: primary_tenant_node}}, state) do
    Logger.info("[TenantReplicaSupervisor] tenant_started: #{slug} (#{id}) on #{primary_tenant_node}")

    new_known = Map.put(state.known_tenants, id, %{slug: slug, node: primary_tenant_node})
    new_state = %{state | known_tenants: new_known}

    if state.spawn_replicas and not Map.has_key?(state.replicas, slug) do
      case state.spawn_fn.(slug, primary_tenant_node) do
        {:ok, replica_info} ->
          info = Map.merge(%{slug: slug, primary_tenant_node: primary_tenant_node, status: :running}, replica_info)
          {:noreply, %{new_state | replicas: Map.put(new_state.replicas, slug, info)}}

        {:error, reason} ->
          Logger.error("[TenantReplicaSupervisor] Failed to spawn replica for #{slug}: #{inspect(reason)}")
          {:noreply, new_state}
      end
    else
      {:noreply, new_state}
    end
  end

  @impl true
  def handle_cast({:tenant_stopped, %{tenant_id: id}}, state) do
    case Map.get(state.known_tenants, id) do
      nil ->
        {:noreply, state}

      %{slug: slug} ->
        Logger.info("[TenantReplicaSupervisor] tenant_stopped: #{slug} (#{id})")

        new_replicas =
          case Map.pop(state.replicas, slug) do
            {nil, replicas} ->
              replicas

            {info, replicas} ->
              stop_peer(info)
              replicas
          end

        new_known = Map.delete(state.known_tenants, id)
        {:noreply, %{state | known_tenants: new_known, replicas: new_replicas}}
    end
  end

  # -- Poll and sync --

  @impl true
  def handle_info(:sync_tenants, state) do
    new_state = sync_with_primary(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:poll, state) do
    new_state = sync_with_primary(state)
    schedule_poll(state.poll_interval_ms)
    {:noreply, new_state}
  end

  # Monitor replica peer processes
  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    case Enum.find(state.replicas, fn {_slug, info} -> Map.get(info, :peer_pid) == pid end) do
      {slug, _info} ->
        Logger.warning("[TenantReplicaSupervisor] Replica peer for #{slug} went down: #{inspect(reason)}")
        new_replicas = Map.delete(state.replicas, slug)
        # Will be re-spawned on next poll
        {:noreply, %{state | replicas: new_replicas}}

      nil ->
        {:noreply, state}
    end
  end

  # -- Private helpers --

  defp sync_with_primary(state) do
    case fetch_tenant_list(state.primary_node) do
      {:ok, tenants} ->
        new_known =
          Enum.reduce(tenants, %{}, fn t, acc ->
            Map.put(acc, t.id, %{slug: t.slug, node: t.node})
          end)

        new_state = %{state | known_tenants: new_known}

        if state.spawn_replicas do
          reconcile_replicas(new_state, tenants)
        else
          new_state
        end

      {:error, reason} ->
        Logger.warning(
          "[TenantReplicaSupervisor] Could not fetch tenant list from primary " <>
            "#{inspect(state.primary_node)}: #{inspect(reason)}"
        )

        state
    end
  end

  defp reconcile_replicas(state, tenants) do
    # Spawn replicas for tenants that don't have one yet
    new_replicas =
      Enum.reduce(tenants, state.replicas, fn t, replicas ->
        if Map.has_key?(replicas, t.slug) do
          replicas
        else
          case state.spawn_fn.(t.slug, t.node) do
            {:ok, replica_info} ->
              Logger.info("[TenantReplicaSupervisor] Spawned replica for #{t.slug}")
              info = Map.merge(%{slug: t.slug, primary_tenant_node: t.node, status: :running}, replica_info)
              Map.put(replicas, t.slug, info)

            {:error, reason} ->
              Logger.error(
                "[TenantReplicaSupervisor] Failed to spawn replica for #{t.slug}: #{inspect(reason)}"
              )

              replicas
          end
        end
      end)

    # Stop replicas for tenants that are no longer on the primary
    primary_slugs = MapSet.new(tenants, & &1.slug)

    {keep, to_stop} =
      Map.split_with(new_replicas, fn {slug, _} -> MapSet.member?(primary_slugs, slug) end)

    for {slug, info} <- to_stop do
      Logger.info("[TenantReplicaSupervisor] Stopping replica for removed tenant #{slug}")
      stop_peer(info)
    end

    %{state | replicas: keep}
  end

  defp fetch_tenant_list(primary_node) do
    case :erpc.call(primary_node, PkiPlatformEngine.TenantLifecycle, :list_tenants, [], 10_000) do
      tenants when is_list(tenants) -> {:ok, tenants}
      other -> {:error, {:unexpected_response, other}}
    end
  rescue
    e -> {:error, {:erpc_failed, Exception.message(e)}}
  catch
    :exit, reason -> {:error, {:erpc_exit, reason}}
  end

  defp stop_peer(info) do
    case Map.get(info, :peer_pid) do
      nil ->
        :ok

      pid ->
        try do
          :peer.stop(pid)
        rescue
          _ -> :ok
        catch
          :exit, _ -> :ok
        end
    end
  end

  defp respawn_as_primary(slug, primary_tenant_node) do
    # Restart the peer without REPLICA_MODE — it will start the full supervision tree
    cookie = Atom.to_string(Node.get_cookie())
    hostname = node() |> Atom.to_string() |> String.split("@") |> List.last()
    replica_node_name = :"tenant_#{slug}@#{hostname}"
    mnesia_dir = "/var/lib/pki/replicas/#{slug}/mnesia"

    args = [
      ~c"-setcookie",
      String.to_charlist(cookie),
      ~c"-name",
      Atom.to_charlist(replica_node_name)
    ]

    env =
      [
        {~c"TENANT_SLUG", String.to_charlist(slug)},
        {~c"MNESIA_DIR", String.to_charlist(mnesia_dir)},
        {~c"RELEASE_COOKIE", String.to_charlist(cookie)}
      ] ++
        if primary_tenant_node do
          [{~c"PRIMARY_TENANT_NODE", Atom.to_charlist(primary_tenant_node)}]
        else
          []
        end

    case :peer.start_link(%{
           name: replica_node_name,
           args: args,
           env: env,
           connection: :standard_io
         }) do
      {:ok, pid, actual_node} ->
        ref = Process.monitor(pid)
        {:ok, %{peer_pid: pid, node: actual_node, monitor_ref: ref}}

      {:ok, pid} ->
        ref = Process.monitor(pid)
        {:ok, %{peer_pid: pid, node: replica_node_name, monitor_ref: ref}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, {:spawn_failed, Exception.message(e)}}
  end

  defp default_spawn(slug, primary_tenant_node) do
    cookie = Atom.to_string(Node.get_cookie())
    hostname = node() |> Atom.to_string() |> String.split("@") |> List.last()
    replica_node_name = :"tenant_#{slug}_replica@#{hostname}"
    mnesia_dir = "/var/lib/pki/replicas/#{slug}/mnesia"

    args = [
      ~c"-setcookie",
      String.to_charlist(cookie),
      ~c"-name",
      Atom.to_charlist(replica_node_name)
    ]

    env = [
      {~c"TENANT_SLUG", String.to_charlist(slug)},
      {~c"MNESIA_DIR", String.to_charlist(mnesia_dir)},
      {~c"PRIMARY_TENANT_NODE", Atom.to_charlist(primary_tenant_node)},
      {~c"REPLICA_MODE", ~c"true"},
      {~c"RELEASE_COOKIE", String.to_charlist(cookie)}
    ]

    case :peer.start_link(%{
           name: replica_node_name,
           args: args,
           env: env,
           connection: :standard_io
         }) do
      {:ok, pid, actual_node} ->
        ref = Process.monitor(pid)
        {:ok, %{peer_pid: pid, node: actual_node, monitor_ref: ref}}

      {:ok, pid} ->
        ref = Process.monitor(pid)
        {:ok, %{peer_pid: pid, node: replica_node_name, monitor_ref: ref}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, {:spawn_failed, Exception.message(e)}}
  end

  defp schedule_poll(interval_ms) do
    Process.send_after(self(), :poll, interval_ms)
  end
end
