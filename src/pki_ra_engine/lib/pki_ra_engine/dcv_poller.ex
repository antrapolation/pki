defmodule PkiRaEngine.DcvPoller do
  @moduledoc """
  GenServer that periodically polls pending DCV challenges.

  Runs every 5 minutes. For each pending challenge, attempts verification.
  Also sweeps expired challenges.

  Disabled in test via `config :pki_ra_engine, start_dcv_poller: false`.
  """

  use GenServer
  require Logger

  @poll_interval 300_000

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  # -- GenServer callbacks --

  @impl true
  def init(_opts) do
    Logger.info("[dcv_poller] Starting DCV poller (interval: #{@poll_interval}ms)")
    schedule_poll()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:poll, state) do
    poll_all_tenants()
    schedule_poll()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # -- Private --

  defp schedule_poll do
    Process.send_after(self(), :poll, @poll_interval)
  end

  defp poll_all_tenants do
    # Poll the default repo (nil tenant) for standalone deployments
    poll_tenant(nil)

    # Poll registered tenants if PlatformEngine is available
    try do
      case PkiPlatformEngine.TenantRegistry.list_tenants() do
        tenants when is_list(tenants) ->
          Enum.each(tenants, fn {tenant_id, _config} ->
            poll_tenant(tenant_id)
          end)

        _ ->
          :ok
      end
    rescue
      _ -> :ok
    end
  end

  defp broadcast_dcv_update(csr_id, challenge) do
    pubsub = Application.get_env(:pki_ra_engine, :dcv_pubsub)

    if pubsub do
      Phoenix.PubSub.broadcast(pubsub, "dcv:#{csr_id}", {:dcv_updated, challenge})
    end
  rescue
    _ -> :ok
  end

  defp poll_tenant(tenant_id) do
    # Expire overdue challenges first
    PkiRaEngine.DcvChallenge.expire_overdue(tenant_id)

    # Verify pending challenges
    pending = PkiRaEngine.DcvChallenge.list_pending(tenant_id)

    Enum.each(pending, fn challenge ->
      case PkiRaEngine.DcvChallenge.verify(tenant_id, challenge.id) do
        {:ok, updated} ->
          if updated.status == "passed" do
            Logger.info(
              "[dcv_poller] Challenge #{challenge.id} passed for #{challenge.domain}"
            )
          end

          broadcast_dcv_update(challenge.csr_id, updated)

        {:error, reason} ->
          Logger.debug(
            "[dcv_poller] Challenge #{challenge.id} verify error: #{inspect(reason)}"
          )
      end
    end)
  rescue
    e ->
      Logger.warning(
        "[dcv_poller] Error polling tenant #{inspect(tenant_id)}: #{Exception.message(e)}"
      )
  end
end
