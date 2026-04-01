defmodule PkiPlatformPortalWeb.PasswordController do
  use PkiPlatformPortalWeb, :controller

  def edit(conn, _params) do
    if get_session(conn, :must_change_password) do
      render(conn, :change_password, layout: false, error: nil)
    else
      redirect(conn, to: "/profile")
    end
  end

  def update(conn, %{"password" => password, "password_confirmation" => confirmation}) do
    admin_id = get_session(conn, :current_user) |> Map.get("id")

    cond do
      String.length(password) < 8 ->
        render(conn, :change_password, layout: false, error: "Password must be at least 8 characters.")

      password != confirmation ->
        render(conn, :change_password, layout: false, error: "Passwords do not match.")

      true ->
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
            render(conn, :change_password, layout: false, error: "Failed: #{inspect(reason)}")
        end
    end
  end

  def update(conn, _params) do
    render(conn, :change_password, layout: false, error: "Password and confirmation are required.")
  end
end
