defmodule PkiPlatformPortalWeb.ForgotPasswordController do
  use PkiPlatformPortalWeb, :controller

  require Logger

  alias PkiPlatformEngine.{AdminManagement, EmailVerification, Mailer, EmailTemplates}

  def new(conn, _params) do
    render(conn, :new, layout: false, error: nil)
  end

  def create(conn, %{"username" => username}) do
    case AdminManagement.get_admin_by_username(username) do
      {:ok, admin} when not is_nil(admin.email) ->
        code = EmailVerification.generate_code(admin.email)
        html = EmailTemplates.password_reset_code(code)
        Mailer.send_email(admin.email, "Password Reset Code", html)
        Logger.info("password_reset_initiated user_id=#{admin.id} remote_ip=#{:inet.ntoa(conn.remote_ip)}")

        conn
        |> configure_session(renew: true)
        |> put_session(:reset_user_id, admin.id)
        |> put_session(:reset_email, admin.email)
        |> render(:code, layout: false, error: nil, masked_email: mask_email(admin.email))

      _ ->
        conn
        |> configure_session(renew: true)
        |> put_session(:reset_user_id, nil)
        |> put_session(:reset_email, nil)
        |> render(:code, layout: false, error: nil, masked_email: "***@***.com")
    end
  end

  def create(conn, _params) do
    conn
    |> configure_session(renew: true)
    |> render(:new, layout: false, error: "Username is required.")
  end

  def update(conn, %{"code" => code, "password" => password, "password_confirmation" => confirmation}) do
    reset_email = get_session(conn, :reset_email)
    reset_user_id = get_session(conn, :reset_user_id)

    cond do
      is_nil(reset_user_id) || is_nil(reset_email) ->
        render(conn, :new, layout: false, error: "Invalid reset session. Please start over.")

      String.length(password) < 8 ->
        render(conn, :code, layout: false, error: "Password must be at least 8 characters.", masked_email: mask_email(reset_email))

      password != confirmation ->
        render(conn, :code, layout: false, error: "Passwords do not match.", masked_email: mask_email(reset_email))

      true ->
        case EmailVerification.verify_code(reset_email, code) do
          :ok ->
            case AdminManagement.reset_admin_password(reset_user_id, password) do
              {:ok, _} ->
                Logger.info("password_reset_completed user_id=#{reset_user_id} remote_ip=#{:inet.ntoa(conn.remote_ip)}")

                conn
                |> delete_session(:reset_user_id)
                |> delete_session(:reset_email)
                |> put_flash(:info, "Password reset successfully. Please sign in.")
                |> redirect(to: "/login")

              {:error, _reason} ->
                render(conn, :code, layout: false, error: "Failed to reset password. Please try again.", masked_email: mask_email(reset_email))
            end

          {:error, :too_many_attempts} ->
            Logger.warning("password_reset_too_many_attempts remote_ip=#{:inet.ntoa(conn.remote_ip)}")

            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "Too many failed attempts. Please start over.")

          {:error, :invalid_code} ->
            render(conn, :code, layout: false, error: "Invalid code. Please try again.", masked_email: mask_email(reset_email))

          {:error, :expired} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "Code expired. Please start over.")

          {:error, :no_code} ->
            conn
            |> delete_session(:reset_user_id)
            |> delete_session(:reset_email)
            |> render(:new, layout: false, error: "No reset code found. Please start over.")
        end
    end
  end

  def update(conn, _params) do
    render(conn, :code, layout: false, error: "All fields are required.", masked_email: "***@***.com")
  end

  defp mask_email(nil), do: "***@***.com"
  defp mask_email(email) do
    case String.split(email, "@") do
      [local, domain] ->
        masked_local = String.slice(local, 0, 2) <> String.duplicate("*", max(String.length(local) - 2, 0))
        masked_local <> "@" <> domain
      _ -> "***@***.com"
    end
  end
end
