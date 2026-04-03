defmodule PkiRaPortalWeb.SessionController do
  use PkiRaPortalWeb, :controller
  import Plug.Conn

  alias PkiRaPortal.RaEngineClient

  # Rate limit login attempts: 5 per 5 minutes per IP
  plug PkiRaPortalWeb.Plugs.RateLimiter,
    [key_prefix: "ra_login", scale_ms: 300_000, limit: 5]
    when action == :create

  def new(conn, _params) do
    render(conn, :login, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    case RaEngineClient.authenticate_with_session(username, password) do
      {:ok, user, session} ->
        cond do
          tenant_suspended?(user) ->
            render(conn, :login, layout: false, error: "Your organization's account has been suspended.")

          user[:must_change_password] && credential_expired?(user) ->
            render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact your platform administrator.")

          user[:must_change_password] ->
            PkiPlatformEngine.PlatformAudit.log("login", %{
              actor_id: user[:id],
              actor_username: user[:username],
              tenant_id: user[:tenant_id],
              portal: "ra",
              details: %{must_change_password: true}
            })

            {:ok, session_id} = create_session_with_detection(conn, user)

            conn
            |> configure_session(renew: true)
            |> put_session(:session_id, session_id)
            |> put_session(:session_key, session[:session_key])
            |> put_session(:session_salt, session[:session_salt])
            |> put_session(:must_change_password, true)
            |> redirect(to: "/change-password")

          true ->
            PkiPlatformEngine.PlatformAudit.log("login", %{
              actor_id: user[:id],
              actor_username: user[:username],
              tenant_id: user[:tenant_id],
              portal: "ra"
            })

            {:ok, session_id} = create_session_with_detection(conn, user)

            conn
            |> configure_session(renew: true)
            |> put_session(:session_id, session_id)
            |> put_session(:session_key, session[:session_key])
            |> put_session(:session_salt, session[:session_salt])
            |> redirect(to: "/")
        end

      {:error, :invalid_credentials} ->
        PkiPlatformEngine.PlatformAudit.log("login_failed", %{
          portal: "ra",
          details: %{username: username}
        })
        render(conn, :login, layout: false, error: "Invalid username or password")

      {:error, reason} ->
        require Logger
        Logger.error("Authentication error: #{inspect(reason)}")
        render(conn, :login, layout: false, error: "Service unavailable. Please try again.")
    end
  end

  def delete(conn, _params) do
    if session_id = get_session(conn, :session_id) do
      PkiRaPortal.SessionStore.delete(session_id)
    end

    conn
    |> clear_session()
    |> redirect(to: "/login")
  end

  defp create_session_with_detection(conn, user) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    # Check for suspicious patterns BEFORE creating session
    existing = PkiRaPortal.SessionStore.list_by_user(user[:id])
    known_ips = existing |> Enum.map(& &1.ip) |> Enum.uniq()

    if ip not in known_ips and length(known_ips) > 0 do
      PkiRaPortal.SessionSecurity.notify(:new_ip_login, %{
        username: user[:username], role: user[:role], ip: ip, portal: "ra"
      })
    end

    if length(existing) > 0 do
      PkiRaPortal.SessionSecurity.notify(:concurrent_sessions, %{
        username: user[:username], role: user[:role],
        session_count: length(existing) + 1, portal: "ra"
      })
    end

    PkiRaPortal.SessionStore.create(%{
      user_id: user[:id],
      username: user[:username],
      role: user[:role],
      tenant_id: user[:tenant_id],
      ip: ip,
      user_agent: ua,
      display_name: user[:display_name],
      email: user[:email]
    })
  end

  defp credential_expired?(%{credential_expires_at: nil}), do: false
  defp credential_expired?(%{credential_expires_at: expires_at}) when is_binary(expires_at) do
    case DateTime.from_iso8601(expires_at) do
      {:ok, dt, _} -> DateTime.compare(DateTime.utc_now(), dt) == :gt
      _ -> false
    end
  end
  defp credential_expired?(%{credential_expires_at: %DateTime{} = expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
  defp credential_expired?(_), do: false

  defp tenant_suspended?(%{tenant_id: nil}), do: false
  defp tenant_suspended?(%{tenant_id: tenant_id}) do
    case PkiPlatformEngine.Provisioner.get_tenant(tenant_id) do
      %{status: "suspended"} -> true
      _ -> false
    end
  rescue
    _ -> false
  end
  defp tenant_suspended?(_), do: false
end
