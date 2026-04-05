defmodule PkiPlatformPortalWeb.PasswordController do
  use PkiPlatformPortalWeb, :controller
  require Logger

  def edit(conn, _params) do
    if get_session(conn, :must_change_password) do
      render(conn, :change_password, layout: false, error: nil)
    else
      redirect(conn, to: "/profile")
    end
  end

  def update(conn, %{"password" => password, "password_confirmation" => confirmation}) do
    session = lookup_session(conn)

    cond do
      String.length(password) < 8 ->
        render(conn, :change_password, layout: false, error: "Password must be at least 8 characters.")

      password != confirmation ->
        render(conn, :change_password, layout: false, error: "Passwords do not match.")

      true ->
        do_change_password(conn, session, password)
    end
  end

  def update(conn, _params) do
    render(conn, :change_password, layout: false, error: "Password and confirmation are required.")
  end

  # --- Private helpers ---

  defp do_change_password(conn, %{role: "tenant_admin", user_id: user_id, tenant_id: tenant_id}, password) do
    case PkiPlatformEngine.PlatformAuth.reset_password(user_id, password, must_change_password: false) do
      {:ok, _user} ->
        conn
        |> delete_session(:must_change_password)
        |> put_flash(:info, "Password changed successfully.")
        |> redirect(to: "/tenants/#{tenant_id}")

      {:error, reason} ->
        Logger.error("[password] Failed to change tenant_admin password: #{inspect(reason)}")
        render(conn, :change_password, layout: false, error: "Failed to change password. Please try again.")
    end
  end

  defp do_change_password(conn, _session, password) do
    admin_id = lookup_session_user_id(conn)

    case PkiPlatformEngine.AdminManagement.reset_admin_password(admin_id, password) do
      {:ok, admin} ->
        # Clear must_change_password flag
        admin
        |> PkiPlatformEngine.PlatformAdmin.changeset(%{must_change_password: false, credential_expires_at: nil})
        |> PkiPlatformEngine.PlatformRepo.update()

        conn
        |> delete_session(:must_change_password)
        |> put_flash(:info, "Password changed successfully.")
        |> redirect(to: "/")

      {:error, reason} ->
        Logger.error("[password] Failed to change password: #{inspect(reason)}")
        render(conn, :change_password, layout: false, error: "Failed to change password. Please try again.")
    end
  end

  defp lookup_session(conn) do
    case get_session(conn, :session_id) do
      nil -> nil
      session_id ->
        case PkiPlatformPortal.SessionStore.lookup(session_id) do
          {:ok, sess} -> sess
          _ -> nil
        end
    end
  end

  defp lookup_session_user_id(conn) do
    case lookup_session(conn) do
      nil -> nil
      sess -> sess.user_id
    end
  end
end
