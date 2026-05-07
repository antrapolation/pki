defmodule PkiTenantWeb.SessionController do
  use PkiTenantWeb, :controller
  import Plug.Conn
  require Logger

  alias PkiMnesia.Structs.PortalUser

  def new(conn, _params) do
    render(conn, :new, layout: false, error: nil)
  end

  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    case PkiMnesia.Repo.get_by(PortalUser, :username, username) do
      {:ok, %PortalUser{} = user} ->
        if verify_password(password, user.password_hash) do
          ip = conn.remote_ip |> :inet.ntoa() |> to_string()
          ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

          portal = detect_portal(conn)

          {:ok, session_id} = PkiTenantWeb.SessionStore.create(%{
            user_id: user.id,
            username: user.username,
            role: to_string(user.role),
            ip: ip,
            user_agent: ua,
            display_name: user.display_name,
            email: user.email,
            portal: portal
          })

          Logger.info("User #{username} logged in via #{portal} portal from #{ip}")

          PkiTenant.AuditBridge.log("user_login", %{
            actor: username,
            actor_role: to_string(user.role),
            ip: ip,
            user_agent: ua,
            portal: portal
          })

          conn
          |> configure_session(renew: true)
          |> put_session(:session_id, session_id)
          |> redirect(to: "/")
        else
          Logger.warning("Failed login attempt for username: #{username}")
          render(conn, :new, layout: false, error: "Invalid username or password")
        end

      {:ok, nil} ->
        # Prevent timing attacks
        Argon2.no_user_verify()
        render(conn, :new, layout: false, error: "Invalid username or password")

      {:error, reason} ->
        Logger.error("User lookup error: #{inspect(reason)}")
        render(conn, :new, layout: false, error: "Service unavailable. Please try again.")
    end
  end

  def delete(conn, _params) do
    if session_id = get_session(conn, :session_id) do
      case PkiTenantWeb.SessionStore.lookup(session_id) do
        {:ok, record} ->
          PkiTenant.AuditBridge.log("user_logout", %{
            actor: record.username,
            actor_role: record.role,
            portal: record.portal
          })

        _ ->
          :ok
      end

      PkiTenantWeb.SessionStore.delete(session_id)
    end

    conn
    |> clear_session()
    |> redirect(to: "/login")
  end

  # --- Private ---

  defp verify_password(password, password_hash) when is_binary(password_hash) do
    cond do
      String.starts_with?(password_hash, "$argon2") ->
        Argon2.verify_pass(password, password_hash)

      String.starts_with?(password_hash, "$2b$") or String.starts_with?(password_hash, "$2a$") ->
        Bcrypt.verify_pass(password, password_hash)

      true ->
        false
    end
  end

  defp verify_password(_password, _hash), do: false

  defp detect_portal(conn) do
    case PkiTenantWeb.HostRouter.extract_service(conn.host) do
      :ra -> "ra"
      _ -> "ca"
    end
  end
end
