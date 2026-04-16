defmodule PkiTenantWeb.Live.AuthHook do
  @moduledoc """
  Unified LiveView on_mount hook for both CA and RA portals.

  Validates the session from the server-side SessionStore,
  enforces role-based access control, and handles session timeout/keep-alive.

  ## Usage in routers

      live_session :ca_authenticated,
        on_mount: [{PkiTenantWeb.Live.AuthHook, :ca}] do
        ...
      end

      live_session :ra_authenticated,
        on_mount: [{PkiTenantWeb.Live.AuthHook, :ra}] do
        ...
      end
  """

  import Phoenix.LiveView
  import Phoenix.Component
  require Logger

  @app :pki_tenant_web

  # CA role-based page access
  @ca_role_pages %{
    "ca_admin" => :all,
    "key_manager" => [
      PkiTenantWeb.Ca.DashboardLive,
      PkiTenantWeb.Ca.IssuerKeysLive,
      PkiTenantWeb.Ca.CeremonyLive,
      PkiTenantWeb.Ca.CeremonyCustodianLive,
      PkiTenantWeb.Ca.CertificatesLive,
      PkiTenantWeb.Ca.HsmDevicesLive,
      PkiTenantWeb.Ca.KeystoresLive,
      PkiTenantWeb.Ca.CaInstancesLive,
      PkiTenantWeb.Ca.ProfileLive
    ],
    "auditor" => [
      PkiTenantWeb.Ca.DashboardLive,
      PkiTenantWeb.Ca.CaInstancesLive,
      PkiTenantWeb.Ca.AuditLogLive,
      PkiTenantWeb.Ca.CeremonyWitnessLive,
      PkiTenantWeb.Ca.ProfileLive
    ]
  }

  # RA portal: all authenticated users can access all pages
  # (RA uses template-level checks via user_role/1 in layout)
  @ra_role_pages %{
    "ra_admin" => :all,
    "ra_officer" => :all,
    "auditor" => :all
  }

  # --- on_mount callbacks ---

  def on_mount(:ca, _params, session, socket) do
    do_mount(:ca, session, socket)
  end

  def on_mount(:ra, _params, session, socket) do
    do_mount(:ra, session, socket)
  end

  def on_mount(:default, _params, session, socket) do
    # Default to CA portal behavior
    do_mount(:ca, session, socket)
  end

  # --- Private ---

  defp do_mount(portal, session, socket) do
    session_id = session["session_id"]

    with {:ok, session_id} when is_binary(session_id) <- {:ok, session_id},
         {:ok, sess} <- PkiTenantWeb.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, sess) do
      PkiTenantWeb.SessionStore.touch(session_id)
      user = session_to_user(sess)

      Logger.metadata(
        user_id: sess.user_id,
        username: sess.username,
        portal: to_string(portal),
        session_id: session_id
      )

      role = to_string(user.role || "auditor")
      view = socket.view
      role_pages = if portal == :ra, do: @ra_role_pages, else: @ca_role_pages

      if allowed?(role, view, role_pages) do
        timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
        warning_ms = timeout_ms - 5 * 60 * 1000

        {timezone, tz_offset_min} = case get_connect_params(socket) do
          %{"timezone" => tz, "timezone_offset" => off} when is_binary(tz) and tz != "" ->
            {tz, off || 0}
          _ ->
            {"UTC", 0}
        end

        {:cont,
         socket
         |> assign(:current_user, user)
         |> assign(:session_id, session_id)
         |> assign(:portal, portal)
         |> assign(:timezone, timezone)
         |> assign(:timezone_offset_min, tz_offset_min)
         |> assign(:session_timeout_ms, timeout_ms)
         |> assign(:session_warning_ms, warning_ms)
         |> attach_hook(:session_keep_alive, :handle_event, fn
           "keep_alive", _params, socket ->
             if sid = socket.assigns[:session_id] do
               PkiTenantWeb.SessionStore.touch(sid)
             end
             {:halt, socket}

           _event, _params, socket ->
             # Touch session on any LiveView interaction
             if sid = socket.assigns[:session_id] do
               PkiTenantWeb.SessionStore.touch(sid)
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
      PkiTenantWeb.SessionStore.delete(session_id)
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
      display_name: sess.display_name,
      email: sess.email
    }
  end

  defp allowed?(role, view, role_pages) do
    case Map.get(role_pages, role) do
      :all -> true
      nil -> false
      pages -> view in pages
    end
  end
end
