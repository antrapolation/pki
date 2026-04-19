defmodule PkiReplica.FailoverManager do
  @moduledoc """
  Manages failover state and promotion of replica tenants.

  State machine:
    :normal -> :primary_down  (triggered by ClusterMonitor)
    :primary_down -> :promoting (when promote_all/0 or promote_tenant/1 called)
    :promoting -> :promoted    (after all promotions complete)

  On primary unreachable:
  1. Logs CRITICAL alert
  2. Writes to alert log file
  3. Fires webhook (if configured)
  4. Sets status to :primary_down
  5. Does NOT auto-promote — operator must call promote_all/0
  """
  use GenServer

  require Logger

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Returns current failover status"
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc "Promotes all replica tenants to primary. Returns list of promoted tenant slugs."
  def promote_all do
    GenServer.call(__MODULE__, :promote_all, 120_000)
  end

  @doc "Promotes a single tenant by slug."
  def promote_tenant(slug) do
    GenServer.call(__MODULE__, {:promote_tenant, slug}, 60_000)
  end

  # -- GenServer callbacks --

  @impl true
  def init(opts) do
    state = %{
      status: :normal,
      promoted_tenants: [],
      webhook_url: Keyword.get(opts, :webhook_url),
      alert_log_path: Keyword.get(opts, :alert_log_path, "/var/log/pki/failover-alert.log"),
      promote_fn: Keyword.get(opts, :promote_fn, &default_promote/1)
    }

    {:ok, state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, state.status, state}
  end

  def handle_call(:promote_all, _from, %{status: status} = state)
      when status in [:primary_down, :promoting] do
    state = %{state | status: :promoting}

    case list_replica_tenants() do
      {:ok, slugs} ->
        promoted =
          Enum.reduce(slugs, state.promoted_tenants, fn slug, acc ->
            case do_promote_tenant(slug, state) do
              :ok ->
                Logger.info("[FailoverManager] Tenant #{slug} promoted to primary")
                [slug | acc]

              {:error, reason} ->
                Logger.error("[FailoverManager] Failed to promote #{slug}: #{inspect(reason)}")
                acc
            end
          end)

        state = %{state | status: :promoted, promoted_tenants: Enum.uniq(promoted)}
        {:reply, {:ok, state.promoted_tenants}, state}

      {:error, reason} ->
        Logger.error("[FailoverManager] Cannot list replica tenants: #{inspect(reason)}")
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:promote_all, _from, %{status: :normal} = state) do
    {:reply, {:error, :primary_not_down}, state}
  end

  def handle_call(:promote_all, _from, %{status: :promoted} = state) do
    {:reply, {:ok, state.promoted_tenants}, state}
  end

  def handle_call({:promote_tenant, slug}, _from, %{status: status} = state)
      when status in [:primary_down, :promoting, :promoted] do
    case do_promote_tenant(slug, state) do
      :ok ->
        promoted = Enum.uniq([slug | state.promoted_tenants])
        Logger.info("[FailoverManager] Tenant #{slug} promoted to primary")
        {:reply, :ok, %{state | promoted_tenants: promoted, status: :promoted}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:promote_tenant, _slug}, _from, %{status: :normal} = state) do
    {:reply, {:error, :primary_not_down}, state}
  end

  @impl true
  def handle_cast({:primary_unreachable}, %{status: :normal} = state) do
    Logger.critical("[CRITICAL] Primary server unreachable - manual promotion required")

    write_alert_log(state.alert_log_path)
    fire_webhook(state.webhook_url)

    {:noreply, %{state | status: :primary_down}}
  end

  def handle_cast({:primary_unreachable}, state) do
    # Already in a failover state, ignore duplicate notifications
    {:noreply, state}
  end

  # -- Internal --

  defp do_promote_tenant(slug, state) do
    state.promote_fn.(slug)
  end

  defp default_promote(slug) do
    # In production, this would:
    # 1. Call PkiMnesia.Schema.promote_to_primary() on the tenant node
    # 2. Start full tenant supervision tree (CA engine, RA engine, Validation, Phoenix)
    # 3. Allocate HTTP port from PortAllocator
    # 4. Update local Caddy config
    Logger.info("[FAILOVER] Tenant #{slug} promoted to primary on replica server")

    with :ok <- promote_mnesia(slug),
         {:ok, _port} <- allocate_port(slug),
         :ok <- start_tenant_engines(slug) do
      :ok
    end
  end

  defp promote_mnesia(_slug) do
    # Would call :rpc to the tenant node: PkiMnesia.Schema.promote_to_primary()
    :ok
  end

  defp allocate_port(slug) do
    PkiReplica.PortAllocator.allocate(slug)
  end

  defp start_tenant_engines(_slug) do
    # Would start the full supervision tree on the tenant node
    :ok
  end

  defp list_replica_tenants do
    # In production, queries the local replica supervisor for known tenant slugs
    # For now, returns empty — TenantReplicaSupervisor (Task 4) will provide this
    {:ok, []}
  end

  defp write_alert_log(path) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
    line = "[#{timestamp}] CRITICAL: Primary server unreachable - manual promotion required\n"

    case File.mkdir_p(Path.dirname(path)) do
      :ok -> File.write(path, line, [:append])
      _ -> :ok
    end
  rescue
    _ -> :ok
  end

  defp fire_webhook(nil), do: :ok

  defp fire_webhook(url) do
    payload =
      Jason.encode!(%{
        event: "primary_unreachable",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        message: "Primary server unreachable - manual promotion required"
      })

    Task.start(fn ->
      try do
        Req.post!(url, body: payload, headers: [{"content-type", "application/json"}])
      rescue
        e ->
          Logger.error("[FailoverManager] Webhook failed: #{inspect(e)}")
      end
    end)
  end
end
