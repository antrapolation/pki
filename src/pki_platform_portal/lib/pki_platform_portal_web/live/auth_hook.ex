defmodule PkiPlatformPortalWeb.Live.AuthHook do
  @moduledoc """
  LiveView on_mount hook that validates the session from the server-side SessionStore.
  """

  import Phoenix.LiveView
  import Phoenix.Component
  require Logger

  @app :pki_platform_portal

  def on_mount(:default, params, session, socket) do
    session_id = session["session_id"]

    with {:ok, session_id} when is_binary(session_id) <- {:ok, session_id},
         {:ok, sess} <- PkiPlatformPortal.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, sess) do
      PkiPlatformPortal.SessionStore.touch(session_id)
      user = session_to_user(sess)

      Logger.metadata(
        user_id: sess.user_id,
        username: sess.username,
        tenant_id: Map.get(sess, :tenant_id),
        portal: "platform",
        session_id: session_id
      )

      timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
      warning_ms = timeout_ms - 5 * 60 * 1000

      {timezone, tz_offset_min} = case get_connect_params(socket) do
        %{"timezone" => tz, "timezone_offset" => off} when is_binary(tz) and tz != "" ->
          {tz, off || 0}
        _ ->
          {"UTC", 0}
      end

      socket =
        socket
        |> assign(:current_user, user)
        |> assign(:tenant_id, sess.tenant_id)
        |> assign(:session_id, session_id)
        |> assign(:timezone, timezone)
        |> assign(:timezone_offset_min, tz_offset_min)
        |> assign(:session_timeout_ms, timeout_ms)
        |> assign(:session_warning_ms, warning_ms)
        |> attach_hook(:session_keep_alive, :handle_event, fn
          "keep_alive", _params, socket ->
            if sid = socket.assigns[:session_id] do
              PkiPlatformPortal.SessionStore.touch(sid)
            end
            {:halt, socket}

          _event, _params, socket ->
            # Touch session on any LiveView interaction
            if sid = socket.assigns[:session_id] do
              PkiPlatformPortal.SessionStore.touch(sid)
            end
            {:cont, socket}
        end)

      # Enforce route scoping for tenant_admin
      case enforce_role_access(sess.role, sess.tenant_id, params, socket) do
        :ok -> {:cont, socket}
        {:redirect, to} -> {:halt, redirect(socket, to: to)}
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
      PkiPlatformPortal.SessionStore.delete(session_id)
      {:error, :expired}
    else
      :ok
    end
  end

  defp session_to_user(sess) do
    %{
      "id" => sess.user_id,
      "username" => sess.username,
      "role" => sess.role,
      "display_name" => sess.display_name,
      "email" => sess.email
    }
  end

  # super_admin has full access
  defp enforce_role_access("super_admin", _tenant_id, _params, _socket), do: :ok

  # tenant_admin is restricted to their tenant detail, dashboard, and profile
  defp enforce_role_access("tenant_admin", tenant_id, params, socket) do
    view = socket.view

    allowed_views = [
      PkiPlatformPortalWeb.TenantDetailLive,
      PkiPlatformPortalWeb.ProfileLive,
      PkiPlatformPortalWeb.DashboardLive
    ]

    cond do
      view not in allowed_views ->
        {:redirect, "/tenants/#{tenant_id}"}

      view == PkiPlatformPortalWeb.TenantDetailLive and Map.get(params, "id") != tenant_id ->
        {:redirect, "/tenants/#{tenant_id}"}

      true ->
        :ok
    end
  end

  defp enforce_role_access(_role, _tenant_id, _params, _socket), do: :ok
end
