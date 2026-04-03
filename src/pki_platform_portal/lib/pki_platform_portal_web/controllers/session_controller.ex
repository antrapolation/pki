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
        cond do
          admin.must_change_password && credential_expired?(admin) ->
            render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact another platform admin.")

          admin.must_change_password ->
            {:ok, session_id} = create_session_with_detection(conn, admin)

            conn
            |> configure_session(renew: true)
            |> put_session(:session_id, session_id)
            |> put_session(:must_change_password, true)
            |> redirect(to: "/change-password")

          true ->
            {:ok, session_id} = create_session_with_detection(conn, admin)

            conn
            |> configure_session(renew: true)
            |> put_session(:session_id, session_id)
            |> redirect(to: "/")
        end

      {:error, _} ->
        render(conn, :login, layout: false, error: "Invalid credentials")
    end
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
