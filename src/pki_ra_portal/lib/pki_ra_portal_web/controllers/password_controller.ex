defmodule PkiRaPortalWeb.PasswordController do
  use PkiRaPortalWeb, :controller

  def edit(conn, _params) do
    if get_session(conn, :must_change_password) do
      render(conn, :change_password, layout: false, error: nil)
    else
      redirect(conn, to: "/profile")
    end
  end

  def update(conn, %{"password" => password, "password_confirmation" => confirmation}) do
    user = lookup_session_user(conn)

    cond do
      String.length(password) < 8 ->
        render(conn, :change_password, layout: false, error: "Password must be at least 8 characters.")

      password != confirmation ->
        render(conn, :change_password, layout: false, error: "Passwords do not match.")

      true ->
        case update_user_password(user, password) do
          :ok ->
            conn
            |> delete_session(:must_change_password)
            |> put_flash(:info, "Password changed successfully.")
            |> redirect(to: "/")

          {:error, reason} ->
            render(conn, :change_password, layout: false, error: "Failed to change password: #{inspect(reason)}")
        end
    end
  end

  def update(conn, _params) do
    render(conn, :change_password, layout: false, error: "Password and confirmation are required.")
  end

  defp update_user_password(user, new_password) do
    user_id = user["id"] || user[:id]

    case PkiPlatformEngine.PlatformAuth.reset_password(user_id, new_password, must_change_password: false) do
      {:ok, _} -> :ok
      {:error, :not_found} -> {:error, "User not found"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp lookup_session_user(conn) do
    case get_session(conn, :session_id) do
      nil -> nil
      session_id ->
        case PkiRaPortal.SessionStore.lookup(session_id) do
          {:ok, sess} -> %{id: sess.user_id, username: sess.username, role: sess.role}
          _ -> nil
        end
    end
  end
end
