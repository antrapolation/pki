defmodule PkiCaPortalWeb.Plugs.RequireAuth do
  @moduledoc """
  Plug that validates the session from the server-side SessionStore.

  Checks:
  1. Session exists in ETS (not revoked/expired)
  2. Session is within idle timeout
  3. User-agent matches (strict — kills session on mismatch)
  4. IP matches (advisory — logs and updates on mismatch)
  """

  import Plug.Conn
  import Phoenix.Controller
  require Logger

  @app :pki_ca_portal

  def init(opts), do: opts

  def call(conn, _opts) do
    session_id = get_session(conn, :session_id)

    with {:ok, session_id} <- ensure_present(session_id),
         {:ok, session} <- PkiCaPortal.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, session),
         :ok <- check_user_agent(conn, session_id, session),
         :ok <- check_ip(conn, session_id, session) do
      PkiCaPortal.SessionStore.touch(session_id)

      conn
      |> assign(:current_user, session_to_user(session))
      |> assign(:session_id, session_id)
    else
      {:error, :no_session} ->
        conn |> redirect(to: "/login") |> halt()

      {:error, :not_found} ->
        conn |> clear_session() |> redirect(to: "/login") |> halt()

      {:error, :expired} ->
        PkiCaPortal.SessionStore.delete(session_id)
        PkiPlatformEngine.PlatformAudit.log("session_expired", %{
          portal: "ca", details: %{session_id: session_id}
        })

        conn
        |> clear_session()
        |> put_flash(:error, "Session expired due to inactivity.")
        |> redirect(to: "/login")
        |> halt()

      {:error, :ua_mismatch} ->
        conn |> clear_session() |> redirect(to: "/login") |> halt()
    end
  end

  defp ensure_present(nil), do: {:error, :no_session}
  defp ensure_present(session_id), do: {:ok, session_id}

  defp check_timeout(_session_id, session) do
    timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
    elapsed = DateTime.diff(DateTime.utc_now(), session.last_active_at, :millisecond)

    if elapsed > timeout_ms, do: {:error, :expired}, else: :ok
  end

  defp check_user_agent(conn, session_id, session) do
    current_ua = get_req_header(conn, "user-agent") |> List.first("")

    if current_ua == session.user_agent do
      :ok
    else
      Logger.warning("[session] UA mismatch for #{session.username}, killing session")
      PkiCaPortal.SessionStore.delete(session_id)

      PkiCaPortal.SessionSecurity.notify(:session_hijack_suspected, %{
        username: session.username,
        role: session.role,
        old_user_agent: session.user_agent,
        new_user_agent: current_ua,
        ip: session.ip,
        portal: "ca"
      })

      {:error, :ua_mismatch}
    end
  end

  defp check_ip(conn, _session_id, session) do
    if not Application.get_env(@app, :session_ip_pinning, true) do
      :ok
    else
      current_ip = conn.remote_ip |> :inet.ntoa() |> to_string()

      if current_ip == session.ip do
        :ok
      else
        Logger.info("[session] IP changed for #{session.username}: #{session.ip} -> #{current_ip}")
        PkiCaPortal.SessionStore.update_ip(session.session_id, current_ip)

        PkiCaPortal.SessionSecurity.notify(:session_ip_changed, %{
          username: session.username,
          role: session.role,
          old_ip: session.ip,
          new_ip: current_ip,
          portal: "ca"
        })

        :ok
      end
    end
  end

  defp session_to_user(session) do
    %{
      id: session.user_id,
      username: session.username,
      role: session.role,
      tenant_id: session.tenant_id,
      display_name: session.display_name,
      email: session.email,
      ca_instance_id: session.ca_instance_id
    }
  end
end
