defmodule PkiPlatformPortal.SessionSecurity do
  @moduledoc """
  Detects suspicious session events and sends async notifications to platform admins.
  """

  require Logger

  @task_supervisor PkiPlatformPortal.TaskSupervisor

  def notify(event, details) do
    # Always log to audit trail (synchronous)
    PkiPlatformEngine.PlatformAudit.log(to_string(event), %{
      portal: details[:portal] || "platform",
      details: details
    })

    # Send email notification (async, fire-and-forget)
    Task.Supervisor.start_child(@task_supervisor, fn ->
      send_admin_notification(event, details)
    end)

    :ok
  rescue
    e ->
      Logger.error("[session_security] Failed to process #{event}: #{inspect(e)}")
      :ok
  end

  defp send_admin_notification(event, details) do
    admins = PkiPlatformEngine.AdminManagement.list_admins()
    emails = admins |> Enum.map(& &1.email) |> Enum.reject(&is_nil/1)

    if emails == [] do
      Logger.warning("[session_security] No admin emails to notify for #{event}")
    else
      subject = "[PKI Security] Suspicious session activity - #{format_event(event)}"
      body = format_email_body(event, details)

      Enum.each(emails, fn email ->
        PkiPlatformEngine.Mailer.send_email(email, subject, body)
      end)
    end
  rescue
    e ->
      Logger.error("[session_security] Failed to send notification email: #{inspect(e)}")
  end

  defp format_event(:session_hijack_suspected), do: "User-Agent Mismatch (Possible Hijack)"
  defp format_event(:session_ip_changed), do: "IP Address Changed"
  defp format_event(:new_ip_login), do: "Login From New IP"
  defp format_event(:concurrent_sessions), do: "Multiple Concurrent Sessions"
  defp format_event(event), do: to_string(event)

  defp format_email_body(event, details) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()

    """
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #b91c1c;">PKI Security Alert</h2>
    <table style="border-collapse: collapse; width: 100%;">
    <tr><td style="padding: 8px; font-weight: bold;">Event</td><td style="padding: 8px;">#{format_event(event)}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">User</td><td style="padding: 8px;">#{details[:username]} (#{details[:role]})</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">Portal</td><td style="padding: 8px;">#{details[:portal]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">Timestamp</td><td style="padding: 8px;">#{timestamp}</td></tr>
    #{event_specific_rows(event, details)}
    </table>
    <p style="color: #6b7280; font-size: 12px; margin-top: 20px;">
    This is an automated security notification from the PKI CA System. Do not reply to this email.
    </p>
    </body></html>
    """
  end

  defp event_specific_rows(:session_hijack_suspected, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">Old User-Agent</td><td style="padding: 8px;">#{details[:old_user_agent]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">New User-Agent</td><td style="padding: 8px;">#{details[:new_user_agent]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">IP</td><td style="padding: 8px;">#{details[:ip]}</td></tr>
    """
  end

  defp event_specific_rows(:session_ip_changed, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">Old IP</td><td style="padding: 8px;">#{details[:old_ip]}</td></tr>
    <tr><td style="padding: 8px; font-weight: bold;">New IP</td><td style="padding: 8px;">#{details[:new_ip]}</td></tr>
    """
  end

  defp event_specific_rows(:new_ip_login, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">IP</td><td style="padding: 8px;">#{details[:ip]}</td></tr>
    """
  end

  defp event_specific_rows(:concurrent_sessions, details) do
    """
    <tr><td style="padding: 8px; font-weight: bold;">Active Sessions</td><td style="padding: 8px;">#{details[:session_count]}</td></tr>
    """
  end

  defp event_specific_rows(_, _), do: ""
end
