defmodule PkiCaEngine.ValidationNotifier do
  @moduledoc """
  Sends certificate lifecycle notifications to the Validation service.

  Notifications are fire-and-forget: errors are logged but never propagate
  to the caller, so they cannot break the signing or revocation flow.
  """

  require Logger

  @notify_issuance_path "/notify/issuance"
  @notify_revocation_path "/notify/revocation"
  @request_timeout_ms 10_000

  @doc """
  Notifies the Validation service that a new certificate has been issued.

  Expects an `%PkiCaEngine.Schema.IssuedCertificate{}` struct (or any map
  containing the required fields).

  Returns `:ok` regardless of outcome. Errors are logged at `:warning` level.
  """
  def notify_issuance(cert) do
    payload = %{
      serial_number: cert.serial_number,
      issuer_key_id: cert.issuer_key_id,
      subject_dn: cert.subject_dn,
      not_before: DateTime.to_iso8601(cert.not_before),
      not_after: DateTime.to_iso8601(cert.not_after)
    }

    case post(@notify_issuance_path, payload) do
      {:ok, %Req.Response{status: status}} when status in 200..299 ->
        Logger.info("Validation service notified of issuance: serial=#{cert.serial_number}")
        :ok

      {:ok, %Req.Response{status: status, body: body}} ->
        Logger.warning(
          "Validation service rejected issuance notification: " <>
            "serial=#{cert.serial_number} status=#{status} body=#{inspect(body)}"
        )

        :ok

      {:error, reason} ->
        Logger.warning(
          "Failed to notify validation service of issuance: " <>
            "serial=#{cert.serial_number} reason=#{inspect(reason)}"
        )

        :ok
    end
  end

  @doc """
  Notifies the Validation service that a certificate has been revoked.

  Returns `:ok` regardless of outcome. Errors are logged at `:warning` level.
  """
  def notify_revocation(serial_number, reason) do
    payload = %{
      serial_number: serial_number,
      reason: reason
    }

    case post(@notify_revocation_path, payload) do
      {:ok, %Req.Response{status: status}} when status in 200..299 ->
        Logger.info("Validation service notified of revocation: serial=#{serial_number}")
        :ok

      {:ok, %Req.Response{status: status, body: body}} ->
        Logger.warning(
          "Validation service rejected revocation notification: " <>
            "serial=#{serial_number} status=#{status} body=#{inspect(body)}"
        )

        :ok

      {:error, reason_err} ->
        Logger.warning(
          "Failed to notify validation service of revocation: " <>
            "serial=#{serial_number} reason=#{inspect(reason_err)}"
        )

        :ok
    end
  end

  # -- Private --

  defp post(path, payload) do
    case validation_url() do
      nil ->
        Logger.debug("Validation URL not configured; skipping notification to #{path}")
        {:ok, %Req.Response{status: 200, body: %{"status" => "skipped"}}}

      base_url ->
        url = String.trim_trailing(base_url, "/") <> path

        Req.post(url,
          json: payload,
          headers: [{"authorization", "Bearer #{internal_api_secret()}"}],
          receive_timeout: @request_timeout_ms,
          retry: false
        )
    end
  rescue
    e ->
      Logger.warning("Unexpected error in ValidationNotifier: #{inspect(e)}")
      {:error, e}
  end

  defp validation_url do
    Application.get_env(:pki_ca_engine, :validation_url)
  end

  defp internal_api_secret do
    Application.get_env(:pki_ca_engine, :internal_api_secret, "")
  end
end
