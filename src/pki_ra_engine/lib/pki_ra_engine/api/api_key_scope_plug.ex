defmodule PkiRaEngine.Api.ApiKeyScopePlug do
  @moduledoc """
  Enforces API key type permissions on routes.
  Internal callers and non-API-key auth bypass scope checks.

  Client keys: submit_csr, view_csr, view_certificates
  Service keys: all client permissions + revoke_certificate, manage_dcv
  """

  import Plug.Conn

  @client_permissions [:submit_csr, :view_csr, :view_certificates]
  @service_permissions @client_permissions ++ [:revoke_certificate, :manage_dcv]

  def init(permission), do: permission

  def call(%Plug.Conn{halted: true} = conn, _permission), do: conn
  def call(%{assigns: %{auth_type: :internal}} = conn, _permission), do: conn

  def call(%{assigns: %{auth_type: :api_key, current_api_key: api_key}} = conn, permission) do
    allowed = case api_key.key_type do
      "service" -> @service_permissions
      "client" -> @client_permissions
      _ -> []
    end

    if permission in allowed do
      conn
    else
      audit_scope_denied(api_key, permission, conn.assigns[:tenant_id])

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(403, Jason.encode!(%{
        error: "scope_denied",
        message: "This API key does not have permission for this operation."
      }))
      |> halt()
    end
  end

  # Unrecognized auth type — deny rather than silently pass
  def call(conn, permission) do
    require Logger
    Logger.warning("api_key_scope_plug: unexpected auth state for permission=#{permission} assigns=#{inspect(Map.keys(conn.assigns))}")

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(403, Jason.encode!(%{
      error: "scope_denied",
      message: "This API key does not have permission for this operation."
    }))
    |> halt()
  end

  defp audit_scope_denied(api_key, permission, tenant_id) do
    PkiPlatformEngine.PlatformAudit.log("api_key_scope_denied", %{
      target_type: "api_key",
      target_id: api_key.id,
      tenant_id: tenant_id,
      portal: "ra",
      details: %{permission: to_string(permission), key_type: api_key.key_type}
    })
  rescue
    _ -> :ok
  end
end
