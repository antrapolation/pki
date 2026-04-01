defmodule PkiPlatformPortalWeb.SessionController do
  use PkiPlatformPortalWeb, :controller

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
            conn
            |> configure_session(renew: true)
            |> put_session(:current_user, serialize_admin(admin))
            |> put_session(:must_change_password, true)
            |> redirect(to: "/change-password")

          true ->
            conn
            |> configure_session(renew: true)
            |> put_session(:current_user, serialize_admin(admin))
            |> redirect(to: "/")
        end

      {:error, _} ->
        render(conn, :login, layout: false, error: "Invalid credentials")
    end
  end

  defp serialize_admin(admin) do
    %{
      "id" => admin.id,
      "username" => admin.username,
      "display_name" => admin.display_name,
      "email" => admin.email,
      "role" => admin.role
    }
  end

  defp credential_expired?(%{credential_expires_at: nil}), do: false
  defp credential_expired?(%{credential_expires_at: %DateTime{} = expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
  defp credential_expired?(_), do: false

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end
end
