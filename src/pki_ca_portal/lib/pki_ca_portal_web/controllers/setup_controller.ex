defmodule PkiCaPortalWeb.SetupController do
  use PkiCaPortalWeb, :controller

  alias PkiCaPortal.CaEngineClient

  def new(conn, params) do
    case validate_tenant(params) do
      {:ok, tenant} ->
        if CaEngineClient.needs_setup?(ca_instance_id()) do
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

  def create(conn, %{"setup" => params, "tenant_slug" => slug}) do
    case validate_tenant(%{"tenant" => slug}) do
      {:ok, tenant} ->
        unless CaEngineClient.needs_setup?(ca_instance_id()) do
          conn
          |> put_flash(:error, "System already configured.")
          |> redirect(to: "/login")
        else
          case validate_setup_params(params) do
            {:ok, attrs} ->
              case CaEngineClient.register_user(ca_instance_id(), Map.put(attrs, :tenant_id, tenant.id)) do
                {:ok, _user} ->
                  render(conn, :setup_complete, layout: false, tenant: tenant)

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

  def create(conn, _params) do
    render(conn, :setup_error, layout: false, message: "Tenant not specified. Contact your platform administrator.")
  end

  defp validate_tenant(%{"tenant" => slug}) when is_binary(slug) and slug != "" do
    case PkiPlatformEngine.Provisioner.get_tenant_by_slug(slug) do
      nil -> {:error, "Tenant not found."}
      %{status: "suspended"} -> {:error, "Tenant is suspended."}
      %{status: "initialized"} -> {:error, "Tenant is not yet activated. Contact your platform administrator."}
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
      role: "ca_admin"
    }}
  end

  defp validate_setup_params(%{"password" => pw, "password_confirmation" => confirm})
       when pw != confirm do
    {:error, "Passwords do not match"}
  end

  defp validate_setup_params(_), do: {:error, "Password must be at least 8 characters"}

  defp ca_instance_id do
    Application.get_env(:pki_ca_portal, :ca_instance_id, "default")
  end

  defp format_changeset_error(error), do: inspect(error)
end
