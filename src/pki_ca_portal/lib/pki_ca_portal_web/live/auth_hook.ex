defmodule PkiCaPortalWeb.Live.AuthHook do
  @moduledoc """
  LiveView on_mount hook that validates the session from the server-side SessionStore
  and enforces role-based access control.
  """

  import Phoenix.LiveView
  import Phoenix.Component

  @app :pki_ca_portal

  @role_pages %{
    "ca_admin" => :all,
    "key_manager" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.HsmDevicesLive,
      PkiCaPortalWeb.KeystoresLive,
      PkiCaPortalWeb.CeremonyLive,
      PkiCaPortalWeb.IssuerKeysLive,
      PkiCaPortalWeb.ProfileLive
    ],
    "auditor" => [
      PkiCaPortalWeb.DashboardLive,
      PkiCaPortalWeb.CaInstancesLive,
      PkiCaPortalWeb.AuditLogLive,
      PkiCaPortalWeb.ProfileLive
    ]
  }

  def on_mount(:default, _params, session, socket) do
    session_id = session["session_id"]

    with {:ok, session_id} when is_binary(session_id) <- {:ok, session_id},
         {:ok, sess} <- PkiCaPortal.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, sess) do
      PkiCaPortal.SessionStore.touch(session_id)
      user = session_to_user(sess)
      role = user.role || "auditor"
      view = socket.view

      if allowed?(role, view) do
        timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
        warning_ms = timeout_ms - 5 * 60 * 1000

        {:cont,
         socket
         |> assign(:current_user, user)
         |> assign(:tenant_id, sess.tenant_id)
         |> assign(:session_id, session_id)
         |> assign(:session_timeout_ms, timeout_ms)
         |> assign(:session_warning_ms, warning_ms)
         |> attach_hook(:session_keep_alive, :handle_event, fn
           "keep_alive", _params, socket ->
             if sid = socket.assigns[:session_id] do
               PkiCaPortal.SessionStore.touch(sid)
             end
             {:halt, socket}

           _event, _params, socket ->
             # Touch session on any LiveView interaction
             if sid = socket.assigns[:session_id] do
               PkiCaPortal.SessionStore.touch(sid)
             end
             {:cont, socket}
         end)}
      else
        {:halt,
         socket
         |> put_flash(:error, "You don't have access to that page.")
         |> redirect(to: "/")}
      end
    else
      _ ->
        {:halt, redirect(socket, to: "/login")}
    end
  end

  defp check_timeout(session_id, session) do
    timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
    elapsed = DateTime.diff(DateTime.utc_now(), session.last_active_at, :millisecond)

    if elapsed > timeout_ms do
      PkiCaPortal.SessionStore.delete(session_id)
      {:error, :expired}
    else
      :ok
    end
  end

  defp session_to_user(sess) do
    %{
      id: sess.user_id,
      username: sess.username,
      role: sess.role,
      tenant_id: sess.tenant_id,
      display_name: sess.display_name,
      email: sess.email,
      ca_instance_id: sess.ca_instance_id
    }
  end

  defp allowed?(role, view) do
    case Map.get(@role_pages, role) do
      :all -> true
      nil -> false
      pages -> view in pages
    end
  end
end
