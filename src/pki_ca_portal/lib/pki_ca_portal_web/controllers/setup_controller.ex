defmodule PkiCaPortalWeb.SetupController do
  use PkiCaPortalWeb, :controller

  alias PkiCaPortal.CaEngineClient

  def new(conn, _params) do
    if CaEngineClient.needs_setup?(1) do
      render(conn, :setup, layout: false, error: nil)
    else
      conn
      |> put_flash(:info, "System already configured.")
      |> redirect(to: "/login")
    end
  end

  def create(conn, %{"setup" => params}) do
    unless CaEngineClient.needs_setup?(1) do
      conn
      |> put_flash(:error, "System already configured.")
      |> redirect(to: "/login")
    else
      case validate_setup_params(params) do
        {:ok, attrs} ->
          case CaEngineClient.register_user(1, attrs) do
            {:ok, _user} ->
              conn
              |> put_flash(:info, "Certificate Authority initialized. Admin account, ACL, and system keypairs created. Please sign in.")
              |> redirect(to: "/login")

            {:error, changeset} ->
              error = format_changeset_error(changeset)
              render(conn, :setup, layout: false, error: error)
          end

        {:error, message} ->
          render(conn, :setup, layout: false, error: message)
      end
    end
  end

  defp validate_setup_params(%{"password" => pw, "password_confirmation" => confirm} = params)
       when pw == confirm and byte_size(pw) >= 8 do
    {:ok, %{
      username: params["username"],
      password: pw,
      display_name: params["display_name"] || params["username"],
      role: "ca_admin"
    }}
  end

  defp validate_setup_params(%{"password" => pw, "password_confirmation" => confirm})
       when pw != confirm do
    {:error, "Passwords do not match"}
  end

  defp validate_setup_params(_), do: {:error, "Password must be at least 8 characters"}

  defp format_changeset_error(error), do: inspect(error)
end
