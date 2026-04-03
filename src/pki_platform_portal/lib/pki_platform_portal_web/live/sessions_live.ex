defmodule PkiPlatformPortalWeb.SessionsLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(PkiCaPortal.PubSub, "session_events")
      Phoenix.PubSub.subscribe(PkiRaPortal.PubSub, "session_events")
      Phoenix.PubSub.subscribe(PkiPlatformPortal.PubSub, "session_events")
    end

    {:ok, assign(socket, :sessions, load_all_sessions())}
  end

  @impl true
  def handle_event("force_logout", %{"portal" => portal, "session-id" => session_id}, socket) do
    admin = socket.assigns.current_user
    store = store_for_portal(portal)

    case store.lookup(session_id) do
      {:ok, session} ->
        store.delete(session_id)

        PkiPlatformEngine.PlatformAudit.log("forced_logout", %{
          portal: portal,
          actor_id: admin[:id] || admin["id"],
          actor_username: admin[:username] || admin["username"],
          details: %{
            target_username: session.username,
            target_session_id: session_id,
            reason: "admin_forced"
          }
        })

      _ ->
        :ok
    end

    {:noreply, assign(socket, :sessions, load_all_sessions())}
  end

  @impl true
  def handle_info({event, _session}, socket)
      when event in [:session_created, :session_deleted, :session_expired] do
    {:noreply, assign(socket, :sessions, load_all_sessions())}
  end

  def handle_info(_, socket), do: {:noreply, socket}

  defp load_all_sessions do
    ca = safe_list(PkiCaPortal.SessionStore, "ca")
    ra = safe_list(PkiRaPortal.SessionStore, "ra")
    platform = safe_list(PkiPlatformPortal.SessionStore, "platform")

    (ca ++ ra ++ platform)
    |> Enum.sort_by(& &1.last_active_at, {:desc, DateTime})
  end

  defp safe_list(store, portal) do
    store.list_all() |> Enum.map(&Map.put(&1, :portal, portal))
  rescue
    _ -> []
  end

  defp store_for_portal("ca"), do: PkiCaPortal.SessionStore
  defp store_for_portal("ra"), do: PkiRaPortal.SessionStore
  defp store_for_portal("platform"), do: PkiPlatformPortal.SessionStore

  defp format_time(nil), do: "—"

  defp format_time(%DateTime{} = dt) do
    Calendar.strftime(dt, "%H:%M:%S")
  end

  defp portal_badge("ca"), do: "badge-primary"
  defp portal_badge("ra"), do: "badge-secondary"
  defp portal_badge("platform"), do: "badge-accent"
  defp portal_badge(_), do: "badge-ghost"

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">Active Sessions</h1>

      <div class="overflow-x-auto">
        <table class="table table-zebra w-full">
          <thead>
            <tr>
              <th>User</th>
              <th>Portal</th>
              <th>Role</th>
              <th>Tenant</th>
              <th>IP</th>
              <th>Login Time</th>
              <th>Last Active</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={session <- @sessions}>
              <td class="font-medium">{session.username}</td>
              <td>
                <span class={"badge #{portal_badge(session.portal)}"}>
                  {session.portal |> String.upcase()}
                </span>
              </td>
              <td>{session.role}</td>
              <td class="text-xs font-mono">{session.tenant_id || "—"}</td>
              <td class="font-mono text-sm">{session.ip}</td>
              <td>{format_time(session.created_at)}</td>
              <td>{format_time(session.last_active_at)}</td>
              <td>
                <button
                  phx-click="force_logout"
                  phx-value-portal={session.portal}
                  phx-value-session-id={session.session_id}
                  data-confirm={"Force logout #{session.username} from #{session.portal}?"}
                  class="btn btn-error btn-xs"
                >
                  Force Logout
                </button>
              </td>
            </tr>
            <tr :if={@sessions == []}>
              <td colspan="8" class="text-center text-base-content/50 py-8">No active sessions</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="mt-4 text-sm text-base-content/50">
        {length(@sessions)} active session(s) across all portals. Updates in real-time.
      </div>
    </div>
    """
  end
end
