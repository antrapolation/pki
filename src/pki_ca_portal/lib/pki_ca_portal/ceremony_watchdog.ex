defmodule PkiCaPortal.CeremonyWatchdog do
  @moduledoc """
  Periodically checks for expired ceremonies and fails them.
  Runs every minute, checks window_expires_at on active ceremonies.
  """

  use GenServer
  require Logger

  alias PkiCaPortal.CaEngineClient
  alias PkiCaPortal.CustodianPasswordStore

  @check_interval_ms 60_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    schedule_check()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:check_expired, state) do
    check_and_fail_expired()
    schedule_check()
    {:noreply, state}
  end

  defp check_and_fail_expired do
    # List all active ceremonies (preparing/generating status)
    # that have passed their window_expires_at
    case CaEngineClient.list_active_ceremonies() do
      {:ok, ceremonies} ->
        now = DateTime.utc_now()

        ceremonies
        |> Enum.filter(fn c ->
          c[:status] in ["preparing", "generating"] and
            c[:window_expires_at] != nil and
            DateTime.compare(now, c[:window_expires_at]) == :gt
        end)
        |> Enum.each(fn ceremony ->
          Logger.warning("[ceremony_watchdog] Expiring ceremony #{ceremony[:id]}")

          # Wipe passwords from ETS
          CustodianPasswordStore.wipe_ceremony(ceremony[:id])

          # Fail the ceremony in DB
          CaEngineClient.fail_ceremony(ceremony[:id], "window_expired")

          # Broadcast failure
          Phoenix.PubSub.broadcast(
            PkiCaPortal.PubSub,
            "ceremony:#{ceremony[:id]}",
            {:ceremony_failed, %{ceremony_id: ceremony[:id], reason: "window_expired"}}
          )

          # Audit log
          PkiPlatformEngine.PlatformAudit.log("ceremony_failed", %{
            portal: "ca",
            details: %{ceremony_id: ceremony[:id], reason: "window_expired"}
          })
        end)

      _ ->
        :ok
    end
  rescue
    e ->
      Logger.error("[ceremony_watchdog] Error checking expired ceremonies: #{inspect(e)}")
  end

  defp schedule_check do
    Process.send_after(self(), :check_expired, @check_interval_ms)
  end
end
