defmodule PkiRaEngine.WebhookDelivery do
  @moduledoc """
  Delivers webhook events to API key-configured callback URLs.
  Retries with exponential backoff. HMAC-SHA256 signed payloads.
  All deliveries are audit-logged.
  """

  require Logger

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.RaApiKey

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
        %{webhook_url: url, webhook_secret: secret}
        when is_binary(url) and url != "" and is_binary(secret) and secret != "" ->
          payload = Map.merge(%{
            event: event,
            csr_id: csr.id,
            subject_dn: csr.subject_dn,
            status: csr.status,
            timestamp: DateTime.to_iso8601(DateTime.utc_now())
          }, extra_payload)

          Task.Supervisor.start_child(PkiRaEngine.TaskSupervisor, fn ->
            deliver_with_retry(url, secret, event, payload, tenant_id, 0)
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

  defp deliver_with_retry(url, secret, event, payload, tenant_id, attempt) do
    body = Jason.encode!(payload)
    timestamp = DateTime.to_iso8601(DateTime.utc_now())
    signature = compute_signature(secret, timestamp, body)

    headers = [
      {"content-type", "application/json"},
      {"x-webhook-signature", signature},
      {"x-webhook-event", to_string(event)},
      {"x-webhook-timestamp", timestamp}
    ]

    case Req.post(url, body: body, headers: headers, receive_timeout: @timeout_ms) do
      {:ok, %{status: status}} when status in 200..299 ->
        Logger.info("webhook_delivered event=#{event} url=#{url} status=#{status} attempt=#{attempt + 1}")
        audit_webhook("webhook_delivered", tenant_id, %{event: event, url: url, status: status, attempt: attempt + 1})

      {:ok, %{status: status}} ->
        Logger.warning("webhook_failed event=#{event} url=#{url} status=#{status} attempt=#{attempt + 1}")
        maybe_retry(url, secret, event, payload, tenant_id, attempt, "HTTP #{status}")

      {:error, reason} ->
        Logger.warning("webhook_failed event=#{event} url=#{url} error=#{inspect(reason)} attempt=#{attempt + 1}")
        maybe_retry(url, secret, event, payload, tenant_id, attempt, inspect(reason))
    end
  rescue
    e ->
      Logger.error("webhook_crash event=#{event} url=#{url} error=#{Exception.message(e)}")
      maybe_retry(url, secret, event, payload, tenant_id, attempt, Exception.message(e))
  end

  defp maybe_retry(url, secret, event, payload, tenant_id, attempt, error) do
    if attempt < @max_retries - 1 do
      delay = Enum.at(@backoff_ms, attempt, 30_000)
      Process.sleep(delay)
      deliver_with_retry(url, secret, event, payload, tenant_id, attempt + 1)
    else
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
