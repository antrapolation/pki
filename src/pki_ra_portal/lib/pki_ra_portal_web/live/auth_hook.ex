defmodule PkiRaPortalWeb.Live.AuthHook do
  @moduledoc """
  LiveView on_mount hook that validates the session from the server-side SessionStore.
  """

  import Phoenix.LiveView
  import Phoenix.Component
  require Logger

  @app :pki_ra_portal

  def on_mount(:default, _params, session, socket) do
    session_id = session["session_id"]

    with {:ok, session_id} when is_binary(session_id) <- {:ok, session_id},
         {:ok, sess} <- PkiRaPortal.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, sess) do
      PkiRaPortal.SessionStore.touch(session_id)
      user = session_to_user(sess)

      Logger.metadata(
        user_id: sess.user_id,
        username: sess.username,
        tenant_id: sess.tenant_id,
        portal: "ra",
        session_id: session_id
      )

      timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
      warning_ms = timeout_ms - 5 * 60 * 1000

      base_socket =
        socket
        |> assign(:current_user, user)
        |> assign(:tenant_id, sess.tenant_id)
        |> assign(:session_id, session_id)
        |> assign(:session_timeout_ms, timeout_ms)
        |> assign(:session_warning_ms, warning_ms)
        |> attach_hook(:session_keep_alive, :handle_event, fn
          "keep_alive", _params, socket ->
            if sid = socket.assigns[:session_id] do
              PkiRaPortal.SessionStore.touch(sid)
            end
            {:halt, socket}

          _event, _params, socket ->
            # Touch session on any LiveView interaction
            if sid = socket.assigns[:session_id] do
              PkiRaPortal.SessionStore.touch(sid)
            end
            {:cont, socket}
        end)

      # First-login redirect: if ra_admin and setup not done, redirect to /welcome
      # Pages that should not trigger the first-login redirect
      # DashboardLive included so "Skip" from welcome screen works
      skip_modules = [
        PkiRaPortalWeb.WelcomeLive,
        PkiRaPortalWeb.SetupWizardLive,
        PkiRaPortalWeb.CaConnectionLive,
        PkiRaPortalWeb.CertProfilesLive,
        PkiRaPortalWeb.DashboardLive,
        PkiRaPortalWeb.ProfileLive
      ]

      if user[:role] == "ra_admin" and socket.view not in skip_modules and needs_setup?(base_socket) do
        {:halt, redirect(base_socket, to: "/welcome")}
      else
        {:cont, base_socket}
      end
    else
      _ ->
        {:halt, redirect(socket, to: "/login")}
    end
  end

  defp needs_setup?(socket) do
    opts = [tenant_id: socket.assigns[:current_user][:tenant_id] || socket.assigns[:current_user]["tenant_id"]]

    has_connections =
      case PkiRaPortal.RaEngineClient.list_ca_connections([], opts) do
        {:ok, conns} -> length(conns) > 0
        _ -> false
      end

    has_profiles =
      case PkiRaPortal.RaEngineClient.list_cert_profiles(opts) do
        {:ok, profiles} -> length(profiles) > 0
        _ -> false
      end

    not (has_connections and has_profiles)
  end

  defp check_timeout(session_id, session) do
    timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
    elapsed = DateTime.diff(DateTime.utc_now(), session.last_active_at, :millisecond)

    if elapsed > timeout_ms do
      PkiRaPortal.SessionStore.delete(session_id)
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
      email: sess.email
    }
  end
end
