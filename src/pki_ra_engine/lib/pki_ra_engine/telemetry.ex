defmodule PkiRaEngine.Telemetry do
  @moduledoc """
  Telemetry instrumentation for the RA Engine.

  Emits events at enforcement points (auth, rate limit, IP whitelist, scope),
  CSR lifecycle transitions, and webhook deliveries.

  Attaches a default handler that maintains ETS counters for dashboard display.
  """

  require Logger

  @ets_table :pki_ra_telemetry_counters

  # ── Event Names ────────────────────────────────────────────────────

  @auth_success [:pki, :ra, :auth, :success]
  @auth_failure [:pki, :ra, :auth, :failure]
  @rate_limit_allow [:pki, :ra, :rate_limit, :allow]
  @rate_limit_deny [:pki, :ra, :rate_limit, :deny]
  @ip_whitelist_allow [:pki, :ra, :ip_whitelist, :allow]
  @ip_whitelist_deny [:pki, :ra, :ip_whitelist, :deny]
  @scope_allow [:pki, :ra, :scope, :allow]
  @scope_deny [:pki, :ra, :scope, :deny]
  @csr_submitted [:pki, :ra, :csr, :submitted]
  @csr_approved [:pki, :ra, :csr, :approved]
  @csr_rejected [:pki, :ra, :csr, :rejected]
  @csr_issued [:pki, :ra, :csr, :issued]
  @webhook_delivered [:pki, :ra, :webhook, :delivered]
  @webhook_failed [:pki, :ra, :webhook, :failed]
  @webhook_exhausted [:pki, :ra, :webhook, :exhausted]

  # ── Public API ─────────────────────────────────────────────────────

  @doc "Initialize ETS table and attach handlers. Call from Application.start."
  def setup do
    if :ets.whereis(@ets_table) == :undefined do
      :ets.new(@ets_table, [:named_table, :public, :set, read_concurrency: true])
    end

    events = [
      @auth_success, @auth_failure,
      @rate_limit_allow, @rate_limit_deny,
      @ip_whitelist_allow, @ip_whitelist_deny,
      @scope_allow, @scope_deny,
      @csr_submitted, @csr_approved, @csr_rejected, @csr_issued,
      @webhook_delivered, @webhook_failed, @webhook_exhausted
    ]

    :telemetry.attach_many("pki-ra-engine-metrics", events, &handle_event/4, nil)
  end

  @doc "Emit a telemetry event."
  def emit(event_name, measurements \\ %{}, metadata \\ %{}) do
    :telemetry.execute(event_name, measurements, metadata)
  end

  # Convenience emitters
  def auth_success(meta), do: emit(@auth_success, %{count: 1}, meta)
  def auth_failure(meta), do: emit(@auth_failure, %{count: 1}, meta)
  def rate_limit_allow(meta), do: emit(@rate_limit_allow, %{count: 1}, meta)
  def rate_limit_deny(meta), do: emit(@rate_limit_deny, %{count: 1}, meta)
  def ip_allow(meta), do: emit(@ip_whitelist_allow, %{count: 1}, meta)
  def ip_deny(meta), do: emit(@ip_whitelist_deny, %{count: 1}, meta)
  def scope_allow(meta), do: emit(@scope_allow, %{count: 1}, meta)
  def scope_deny(meta), do: emit(@scope_deny, %{count: 1}, meta)
  def csr_submitted(meta), do: emit(@csr_submitted, %{count: 1}, meta)
  def csr_approved(meta), do: emit(@csr_approved, %{count: 1}, meta)
  def csr_rejected(meta), do: emit(@csr_rejected, %{count: 1}, meta)
  def csr_issued(meta), do: emit(@csr_issued, %{count: 1}, meta)
  def webhook_delivered(meta), do: emit(@webhook_delivered, %{count: 1}, meta)
  def webhook_failed(meta), do: emit(@webhook_failed, %{count: 1}, meta)
  def webhook_exhausted(meta), do: emit(@webhook_exhausted, %{count: 1}, meta)

  @doc "Get current counter values as a map."
  def get_metrics do
    try do
      :ets.tab2list(@ets_table) |> Map.new()
    rescue
      _ -> %{}
    end
  end

  @doc "Get a single counter value."
  def get_counter(key) do
    try do
      case :ets.lookup(@ets_table, key) do
        [{^key, val}] -> val
        _ -> 0
      end
    rescue
      _ -> 0
    end
  end

  # ── Handler ────────────────────────────────────────────────────────

  def handle_event(event, _measurements, _metadata, _config) do
    key = event |> Enum.join(".")
    try do
      :ets.update_counter(@ets_table, key, {2, 1}, {key, 0})
    rescue
      _ -> :ok
    end
  end
end
