defmodule PkiRaEngine.WebhookDelivery do
  @moduledoc """
  Delivers webhook events to API key-configured callback URLs.
  Retries with exponential backoff. HMAC-SHA256 signed payloads.
  All deliveries are audit-logged.
  """

  require Logger

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.RaApiKey
  alias PkiRaEngine.Schema.WebhookDelivery, as: WebhookRecord

  @max_retries 3
  @backoff_ms [1_000, 5_000, 30_000]
  @timeout_ms 10_000

  @doc """
  Deliver a webhook event for a CSR.
  Looks up the API key's webhook_url from submitted_by_key_id.
  Fire-and-forget — never fails the caller.
  """
  def deliver_for_csr(tenant_id, csr, event, extra_payload \\ %{}) do
    if csr.submitted_by_key_id do
      repo = TenantRepo.ra_repo(tenant_id)

      case repo.get(RaApiKey, csr.submitted_by_key_id) do
        %{webhook_url: url, webhook_secret: secret} = api_key
        when is_binary(url) and url != "" and is_binary(secret) and secret != "" ->
          payload = Map.merge(%{
            event: event,
            csr_id: csr.id,
            subject_dn: csr.subject_dn,
            status: csr.status,
            timestamp: PkiRaEngine.Api.ConnHelpers.format_datetime(DateTime.utc_now())
          }, extra_payload)

          # Persist delivery record
          record = persist_delivery(repo, api_key.id, csr.id, event, url, payload)

          Task.Supervisor.start_child(PkiRaEngine.TaskSupervisor, fn ->
            deliver_with_retry(url, secret, event, payload, tenant_id, 0, record)
          end)

        _ ->
          :ok
      end
    else
      :ok
    end
  rescue
    e ->
      Logger.error("webhook_deliver_for_csr_failed event=#{event} error=#{Exception.message(e)}")
      :ok
  end

  @doc """
  Deliver a webhook for a certificate event (by serial number).
  Finds the originating CSR to look up the API key's webhook config.
  """
  def deliver_for_cert(tenant_id, serial_number, event, payload) do
    import Ecto.Query

    repo = TenantRepo.ra_repo(tenant_id)

    case repo.one(
           from(c in PkiRaEngine.Schema.CsrRequest,
             where: c.issued_cert_serial == ^serial_number and not is_nil(c.submitted_by_key_id),
             limit: 1
           )
         ) do
      %{} = csr ->
        deliver_for_csr(tenant_id, csr, event, payload)

      _ ->
        :ok
    end
  rescue
    e ->
      Logger.error("webhook_deliver_for_cert_failed event=#{event} error=#{Exception.message(e)}")
      :ok
  end

  # ── Private ──────────────────────────────────────────────────────────

  defp deliver_with_retry(url, secret, event, payload, tenant_id, attempt, record \\ nil) do
    body = Jason.encode!(payload)
    timestamp = PkiRaEngine.Api.ConnHelpers.format_datetime(DateTime.utc_now())
    signature = compute_signature(secret, timestamp, body)

    headers = [
      {"content-type", "application/json"},
      {"x-webhook-signature", signature},
      {"x-webhook-event", to_string(event)},
      {"x-webhook-timestamp", timestamp}
    ]

    case Req.post(url, body: body, headers: headers, receive_timeout: @timeout_ms) do
      {:ok, %{status: status}} when status in 200..299 ->
        update_record(record, tenant_id, %{status: "delivered", attempts: attempt + 1, last_http_status: status})
        PkiRaEngine.Telemetry.webhook_delivered(%{event: event, url: url, attempt: attempt + 1})
        Logger.info("webhook_delivered event=#{event} url=#{url} status=#{status} attempt=#{attempt + 1}")
        audit_webhook("webhook_delivered", tenant_id, %{event: event, url: url, status: status, attempt: attempt + 1})

      {:ok, %{status: status}} ->
        Logger.warning("webhook_failed event=#{event} url=#{url} status=#{status} attempt=#{attempt + 1}")
        maybe_retry(url, secret, event, payload, tenant_id, attempt, "HTTP #{status}", record)

      {:error, reason} ->
        Logger.warning("webhook_failed event=#{event} url=#{url} error=#{inspect(reason)} attempt=#{attempt + 1}")
        maybe_retry(url, secret, event, payload, tenant_id, attempt, inspect(reason), record)
    end
  rescue
    e ->
      Logger.error("webhook_crash event=#{event} url=#{url} error=#{Exception.message(e)}")
      maybe_retry(url, secret, event, payload, tenant_id, attempt, Exception.message(e), record)
  end

  defp maybe_retry(url, secret, event, payload, tenant_id, attempt, error, record) do
    if attempt < @max_retries - 1 do
      update_record(record, tenant_id, %{status: "failed", attempts: attempt + 1, last_error: error})
      delay = Enum.at(@backoff_ms, attempt, 30_000)
      Process.sleep(delay)
      deliver_with_retry(url, secret, event, payload, tenant_id, attempt + 1, record)
    else
      update_record(record, tenant_id, %{status: "exhausted", attempts: attempt + 1, last_error: error})
      PkiRaEngine.Telemetry.webhook_exhausted(%{event: event, url: url})
      Logger.error("webhook_exhausted event=#{event} url=#{url} attempts=#{@max_retries}")
      audit_webhook("webhook_failed", tenant_id, %{event: event, url: url, error: error, attempts_exhausted: true})
    end
  end

  defp compute_signature(secret, timestamp, body) do
    # Sign "timestamp.body" per Stripe/GitHub pattern — prevents replay attacks
    signed_content = "#{timestamp}.#{body}"
    digest = :crypto.mac(:hmac, :sha256, secret, signed_content) |> Base.encode16(case: :lower)
    "sha256=#{digest}"
  end

  defp persist_delivery(repo, api_key_id, csr_id, event, url, payload) do
    attrs = %{
      api_key_id: api_key_id,
      csr_id: csr_id,
      event: event,
      url: url,
      status: "pending",
      payload: payload
    }

    case %WebhookRecord{} |> WebhookRecord.changeset(attrs) |> repo.insert() do
      {:ok, record} -> record
      {:error, _} -> nil
    end
  rescue
    _ -> nil
  end

  defp update_record(nil, _tenant_id, _attrs), do: :ok
  defp update_record(%{id: record_id}, tenant_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    # Re-fetch by ID to avoid stale struct issues across sleep/retry cycles
    case repo.get(WebhookRecord, record_id) do
      nil -> :ok
      fresh -> fresh |> WebhookRecord.changeset(attrs) |> repo.update()
    end
  rescue
    _ -> :ok
  end

  @doc "List webhook deliveries for an API key."
  def list_deliveries(tenant_id, api_key_id, opts \\ []) do
    import Ecto.Query

    repo = TenantRepo.ra_repo(tenant_id)
    limit = Keyword.get(opts, :limit, 50)

    from(d in WebhookRecord,
      where: d.api_key_id == ^api_key_id,
      order_by: [desc: d.inserted_at],
      limit: ^limit
    )
    |> repo.all()
  end

  @doc "List dead letter (exhausted) deliveries."
  def list_dead_letters(tenant_id, opts \\ []) do
    import Ecto.Query

    repo = TenantRepo.ra_repo(tenant_id)
    limit = Keyword.get(opts, :limit, 50)

    from(d in WebhookRecord,
      where: d.status == "exhausted",
      order_by: [desc: d.inserted_at],
      limit: ^limit
    )
    |> repo.all()
  end

  defp audit_webhook(action, tenant_id, details) do
    PkiPlatformEngine.PlatformAudit.log(action, %{
      tenant_id: tenant_id,
      portal: "ra",
      details: details
    })
  rescue
    _ -> :ok
  end
end
