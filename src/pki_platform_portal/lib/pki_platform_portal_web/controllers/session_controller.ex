defmodule PkiPlatformPortalWeb.SessionController do
  use PkiPlatformPortalWeb, :controller
  require Logger

  # Rate limit login attempts: 5 per 5 minutes per IP
  plug PkiPlatformPortalWeb.Plugs.RateLimiter,
    [key_prefix: "platform_login", scale_ms: 300_000, limit: 5]
    when action == :create

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    case PkiPlatformEngine.AdminManagement.authenticate(username, password) do
      {:ok, admin} ->
        handle_superadmin_login(conn, admin)

      {:error, _} ->
        # Try tenant_admin authentication
        case PkiPlatformEngine.PlatformAuth.authenticate_tenant_admin(username, password) do
          {:ok, user, role} ->
            handle_tenant_admin_login(conn, user, role)

          {:error, _} ->
            log_failed_login(conn, username)
            render(conn, :login, layout: false, error: "Invalid credentials")
        end
    end
  end

  defp handle_superadmin_login(conn, admin) do
    cond do
      admin.must_change_password && credential_expired?(admin) ->
        render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact another platform admin.")

      admin.must_change_password ->
        log_login(conn, admin)
        {:ok, session_id} = create_session_with_detection(conn, admin)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> put_session(:must_change_password, true)
        |> redirect(to: "/change-password")

      true ->
        log_login(conn, admin)
        {:ok, session_id} = create_session_with_detection(conn, admin)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> redirect(to: "/")
    end
  end

  defp handle_tenant_admin_login(conn, user, role) do
    cond do
      user.must_change_password && credential_expired?(user) ->
        render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact your platform admin.")

      user.must_change_password ->
        log_login(conn, user)
        {:ok, session_id} = create_tenant_admin_session(conn, user, role)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> put_session(:must_change_password, true)
        |> redirect(to: "/change-password")

      true ->
        log_login(conn, user)
        {:ok, session_id} = create_tenant_admin_session(conn, user, role)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> redirect(to: "/tenants/#{role.tenant_id}")
    end
  end

  defp create_tenant_admin_session(conn, user, role) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    PkiPlatformPortal.SessionStore.create(%{
      user_id: user.id,
      username: user.username,
      role: "tenant_admin",
      tenant_id: role.tenant_id,
      ip: ip,
      user_agent: ua,
      display_name: user.display_name,
      email: user.email
    })
  end

  defp log_login(conn, user) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    PkiPlatformEngine.PlatformAudit.log("login", %{
      actor_id: user.id,
      actor_username: user.username,
      portal: "platform",
      details: %{ip: ip, user_agent: ua}
    })
  end

  defp log_failed_login(conn, username) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    PkiPlatformEngine.PlatformAudit.log("login_failed", %{
      portal: "platform",
      details: %{username: username, ip: ip, user_agent: ua}
    })
  end

  defp create_session_with_detection(conn, admin) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    # Check for suspicious patterns BEFORE creating session
    existing = PkiPlatformPortal.SessionStore.list_by_user(admin.id)
    known_ips = existing |> Enum.map(& &1.ip) |> Enum.uniq()

    if ip not in known_ips and length(known_ips) > 0 do
      PkiPlatformPortal.SessionSecurity.notify(:new_ip_login, %{
        username: admin.username, role: admin.role, ip: ip, portal: "platform"
      })
    end

    if length(existing) > 0 do
      PkiPlatformPortal.SessionSecurity.notify(:concurrent_sessions, %{
        username: admin.username, role: admin.role,
        session_count: length(existing) + 1, portal: "platform"
      })
    end

    PkiPlatformPortal.SessionStore.create(%{
      user_id: admin.id,
      username: admin.username,
      role: admin.role,
      tenant_id: nil,
      ip: ip,
      user_agent: ua,
      display_name: admin.display_name,
      email: admin.email
    })
  end

  defp credential_expired?(%{credential_expires_at: nil}), do: false
  defp credential_expired?(%{credential_expires_at: %DateTime{} = expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
  defp credential_expired?(_), do: false

  def delete(conn, _params) do
    if session_id = get_session(conn, :session_id) do
      PkiPlatformPortal.SessionStore.delete(session_id)
    end

    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
