defmodule PkiRaPortalWeb.SetupController do
  use PkiRaPortalWeb, :controller

  alias PkiRaPortal.RaEngineClient

  def new(conn, params) do
    case validate_tenant(params) do
      {:ok, tenant} ->
        if RaEngineClient.needs_setup?(tenant.id) do
          render(conn, :setup, layout: false, error: nil, tenant: tenant)
        else
          conn
          |> put_flash(:info, "System already configured.")
          |> redirect(to: "/login")
        end

      {:error, message} ->
        render(conn, :setup_error, layout: false, message: message)
    end
  end

  def create(conn, %{"setup" => params}) do
    case validate_tenant(params) do
      {:ok, tenant} ->
        unless RaEngineClient.needs_setup?(tenant.id) do
          conn
          |> put_flash(:error, "System already configured.")
          |> redirect(to: "/login")
        else
          case validate_setup_params(params) do
            {:ok, attrs} ->
              case RaEngineClient.register_user(Map.put(attrs, :tenant_id, tenant.id)) do
                {:ok, _user} ->
                  conn
                  |> put_flash(:info, "Admin account created. Please sign in.")
                  |> redirect(to: "/login")

                {:error, changeset} ->
                  error = format_changeset_error(changeset)
                  render(conn, :setup, layout: false, error: error, tenant: tenant)
              end

            {:error, message} ->
              render(conn, :setup, layout: false, error: message, tenant: tenant)
          end
        end

      {:error, message} ->
        render(conn, :setup_error, layout: false, message: message)
    end
  end

  defp validate_tenant(%{"tenant" => slug}) when is_binary(slug) and slug != "" do
    case PkiPlatformEngine.Provisioner.get_tenant_by_slug(slug) do
      nil -> {:error, "Tenant not found."}
      %{status: "suspended"} -> {:error, "Tenant is suspended."}
      tenant -> {:ok, tenant}
    end
  end

  defp validate_tenant(_), do: {:error, "Tenant not specified. Contact your platform administrator."}

  defp validate_setup_params(%{"password" => pw, "password_confirmation" => confirm} = params)
       when pw == confirm and byte_size(pw) >= 8 do
    {:ok, %{
      username: params["username"],
      password: pw,
      display_name: params["display_name"] || params["username"],
      role: "ra_admin"
    }}
  end

  defp validate_setup_params(%{"password" => pw, "password_confirmation" => confirm})
       when pw != confirm do
    {:error, "Passwords do not match"}
  end

  defp validate_setup_params(_), do: {:error, "Password must be at least 8 characters"}

  defp format_changeset_error(error), do: inspect(error)
end
