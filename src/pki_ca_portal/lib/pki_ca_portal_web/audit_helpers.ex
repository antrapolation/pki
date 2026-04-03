defmodule PkiCaPortalWeb.AuditHelpers do
  @moduledoc "Shared audit logging helper for CA portal LiveViews."

  alias PkiPlatformEngine.PlatformAudit
  require Logger

  def audit_log(socket, action, target_type, target_id, details \\ %{}) do
    user = socket.assigns.current_user

    case PlatformAudit.log(action, %{
      actor_id: user[:id] || user["id"],
      actor_username: user[:username] || user["username"],
      target_type: target_type,
      target_id: target_id,
      tenant_id: socket.assigns[:tenant_id],
      portal: "ca",
      details: details
    }) do
      {:ok, _} -> :ok
      {:error, changeset} ->
        Logger.error("[audit] Failed to persist event #{action}: #{inspect(changeset.errors)}")
        :error
    end
  end
end
