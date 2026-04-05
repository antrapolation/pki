defmodule PkiRaEngine.CsrReconciler do
  @moduledoc """
  Periodic reconciliation sweep for CSRs stuck in "approved" status.

  Detects CSRs that were approved but never issued (e.g. due to CA downtime
  or node crash during async forward_to_ca) and retries forwarding.

  Threshold must exceed both the sweep interval and expected maximum CA signing
  time to avoid duplicate forwarding while the original async task is still running.
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.CsrRequest
  alias PkiRaEngine.CsrValidation

  @sweep_interval_ms :timer.minutes(5)
  # Must be > sweep_interval + expected max CA signing time to avoid double-forward
  @stuck_threshold_ms :timer.minutes(10)

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    schedule_sweep()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep_all_tenants()
    schedule_sweep()
    {:noreply, state}
  end

  defp schedule_sweep do
    interval = Application.get_env(:pki_ra_engine, :csr_reconcile_interval_ms, @sweep_interval_ms)
    Process.send_after(self(), :sweep, interval)
  end

  defp sweep_all_tenants do
    # Sweep default tenant; multi-tenant sweeps added when TenantRepo gains tenant enumeration
    sweep_tenant(nil)
  rescue
    e ->
      Logger.error("csr_reconciler_sweep_failed error=#{Exception.message(e)}")
  end

  defp sweep_tenant(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)
    threshold = DateTime.add(DateTime.utc_now(), -@stuck_threshold_ms, :millisecond)

    stuck_csrs =
      from(c in CsrRequest,
        where:
          c.status == "approved" and
            (is_nil(c.reviewed_at) or c.reviewed_at < ^threshold),
        order_by: [asc: c.reviewed_at],
        limit: 20
      )
      |> repo.all()

    for csr <- stuck_csrs do
      retry_forward(tenant_id, csr)
    end
  rescue
    e ->
      Logger.error("csr_reconciler_tenant_failed tenant=#{inspect(tenant_id)} error=#{Exception.message(e)}")
  end

  defp retry_forward(tenant_id, csr) do
    Logger.warning("csr_reconciler_retry csr_id=#{csr.id} approved_at=#{csr.reviewed_at}")

    case CsrValidation.forward_to_ca(tenant_id, csr.id) do
      {:ok, _} ->
        Logger.info("csr_reconciler_issued csr_id=#{csr.id}")

      {:error, {:invalid_transition, "issued", _}} ->
        # Already issued (by original async task) — no action needed
        Logger.info("csr_reconciler_already_issued csr_id=#{csr.id}")

      {:error, reason} ->
        Logger.error("csr_reconciler_forward_failed csr_id=#{csr.id} reason=#{inspect(reason)}")

        PkiPlatformEngine.PlatformAudit.log("csr_forward_retry_failed", %{
          target_type: "csr",
          target_id: csr.id,
          tenant_id: tenant_id,
          portal: "ra",
          details: %{reason: inspect(reason)}
        })
    end
  rescue
    e ->
      Logger.error("csr_reconciler_crash csr_id=#{csr.id} error=#{Exception.message(e)}")
  end
end
