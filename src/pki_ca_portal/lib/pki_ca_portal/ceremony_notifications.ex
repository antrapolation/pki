defmodule PkiCaPortal.CeremonyNotifications do
  @moduledoc """
  Sends async email notifications for ceremony events.
  Uses Task.Supervisor for fire-and-forget delivery.
  """

  require Logger

  @task_supervisor PkiCaPortal.TaskSupervisor

  def notify_ceremony_initiated(ceremony, participants) do
    send_async(fn ->
      emails = resolve_emails(participants.custodian_user_ids ++ [participants.auditor_user_id])
      subject = "[PKI Ceremony] You've been assigned to Key Ceremony #{short_id(ceremony.id)}"
      body = ceremony_initiated_body(ceremony)
      send_to_all(emails, subject, body)
    end)
  end

  def notify_custodian_accepted(ceremony, custodian_username, ready_count, total_count) do
    send_async(fn ->
      admin_emails = resolve_admin_emails(ceremony.initiated_by)
      subject = "[PKI Ceremony] #{custodian_username} accepted share (#{ready_count}/#{total_count})"
      body = custodian_accepted_body(ceremony, custodian_username, ready_count, total_count)
      send_to_all(admin_emails, subject, body)
    end)
  end

  def notify_all_custodians_ready(ceremony) do
    send_async(fn ->
      auditor_emails = resolve_emails([ceremony.auditor_user_id])
      subject = "[PKI Ceremony] All custodians ready — please witness preparation"
      body = all_custodians_ready_body(ceremony)
      send_to_all(auditor_emails, subject, body)
    end)
  end

  def notify_witness_attested(ceremony, phase) do
    send_async(fn ->
      admin_emails = resolve_admin_emails(ceremony.initiated_by)
      subject = "[PKI Ceremony] Auditor witnessed #{phase} for Ceremony #{short_id(ceremony.id)}"
      body = witness_attested_body(ceremony, phase)
      send_to_all(admin_emails, subject, body)
    end)
  end

  def notify_ceremony_completed(ceremony, participants) do
    send_async(fn ->
      all_ids = participants.custodian_user_ids ++ [participants.auditor_user_id, ceremony.initiated_by]
      emails = resolve_emails(all_ids)
      subject = "[PKI Ceremony] Ceremony #{short_id(ceremony.id)} completed successfully"
      body = ceremony_completed_body(ceremony)
      send_to_all(emails, subject, body)
    end)
  end

  def notify_ceremony_failed(ceremony, reason, participants) do
    send_async(fn ->
      all_ids = participants.custodian_user_ids ++ [participants.auditor_user_id, ceremony.initiated_by]
      emails = resolve_emails(all_ids)
      subject = "[PKI Ceremony] Ceremony #{short_id(ceremony.id)} failed"
      body = ceremony_failed_body(ceremony, reason)
      send_to_all(emails, subject, body)
    end)
  end

  def notify_window_expiring(ceremony, pending_user_ids) do
    send_async(fn ->
      emails = resolve_emails(pending_user_ids)
      subject = "[PKI Ceremony] Ceremony #{short_id(ceremony.id)} expires in 1 hour"
      body = window_expiring_body(ceremony)
      send_to_all(emails, subject, body)
    end)
  end

  # --- Private ---

  defp send_async(fun) do
    Task.Supervisor.start_child(@task_supervisor, fun)
    :ok
  rescue
    e ->
      Logger.error("[ceremony_notifications] Failed to spawn notification task: #{inspect(e)}")
      :ok
  end

  defp send_to_all(emails, subject, body) do
    emails
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.each(fn email ->
      PkiPlatformEngine.Mailer.send_email(email, subject, body)
    end)
  rescue
    e -> Logger.error("[ceremony_notifications] Failed to send emails: #{inspect(e)}")
  end

  defp resolve_emails(user_ids) do
    # Look up emails from platform admin list and CA user list
    admins = PkiPlatformEngine.AdminManagement.list_admins()
    admin_map = Map.new(admins, fn a -> {a.id, a.email} end)

    user_ids
    |> Enum.map(fn id -> admin_map[id] end)
    |> Enum.reject(&is_nil/1)
  rescue
    _ -> []
  end

  defp resolve_admin_emails(initiator_id) do
    resolve_emails([initiator_id])
  end

  defp short_id(id) when is_binary(id), do: String.slice(id, 0, 8)
  defp short_id(_), do: "unknown"

  defp ceremony_initiated_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>Key Ceremony Assignment</h2>
    <p>You have been assigned to Key Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    <table style="border-collapse: collapse;">
    <tr><td style="padding: 4px 12px; font-weight: bold;">Algorithm</td><td>#{ceremony.algorithm}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">Threshold</td><td>#{ceremony.threshold_k}-of-#{ceremony.threshold_n}</td></tr>
    <tr><td style="padding: 4px 12px; font-weight: bold;">Deadline</td><td>#{ceremony.time_window_hours} hours</td></tr>
    </table>
    <p>Please log in to the CA Portal to complete your part.</p>
    <p style="color: #6b7280; font-size: 12px;">This is an automated notification from the PKI CA System.</p>
    </body></html>
    """
  end

  defp custodian_accepted_body(ceremony, username, ready, total) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>Custodian Share Accepted</h2>
    <p><strong>#{username}</strong> accepted their share for Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    <p>Progress: #{ready}/#{total} custodians ready.</p>
    </body></html>
    """
  end

  defp all_custodians_ready_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>All Custodians Ready</h2>
    <p>All custodians have accepted their shares for Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    <p>Please log in to the CA Portal and witness the preparation phase.</p>
    </body></html>
    """
  end

  defp witness_attested_body(ceremony, phase) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2>Auditor Witness</h2>
    <p>The auditor has witnessed the <strong>#{phase}</strong> phase for Ceremony <strong>#{short_id(ceremony.id)}</strong>.</p>
    </body></html>
    """
  end

  defp ceremony_completed_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #16a34a;">Ceremony Completed</h2>
    <p>Key Ceremony <strong>#{short_id(ceremony.id)}</strong> has been completed successfully.</p>
    <p>Algorithm: #{ceremony.algorithm} | Threshold: #{ceremony.threshold_k}-of-#{ceremony.threshold_n}</p>
    </body></html>
    """
  end

  defp ceremony_failed_body(ceremony, reason) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #dc2626;">Ceremony Failed</h2>
    <p>Key Ceremony <strong>#{short_id(ceremony.id)}</strong> has failed.</p>
    <p>Reason: #{reason}</p>
    </body></html>
    """
  end

  defp window_expiring_body(ceremony) do
    """
    <!DOCTYPE html><html><head><meta charset="utf-8"></head>
    <body style="font-family: sans-serif; padding: 20px;">
    <h2 style="color: #d97706;">Ceremony Expiring Soon</h2>
    <p>Key Ceremony <strong>#{short_id(ceremony.id)}</strong> expires in approximately 1 hour.</p>
    <p>Please log in and complete your part before the deadline.</p>
    </body></html>
    """
  end
end
