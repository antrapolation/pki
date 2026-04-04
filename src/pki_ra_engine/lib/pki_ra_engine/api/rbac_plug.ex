defmodule PkiRaEngine.Api.RbacPlug do
  @moduledoc """
  Plug that enforces role-based access control on authenticated routes.

  Internal callers (portal-to-engine via shared secret) bypass RBAC checks,
  as the portal enforces its own authorization. API key callers are checked
  against the key owner's role and the required permission for the route.
  """

  import Plug.Conn

  alias PkiRaEngine.UserManagement

  def init(permission), do: permission

  def call(%Plug.Conn{assigns: %{auth_type: :internal}} = conn, _permission) do
    # Portal-to-engine calls are trusted; the portal enforces its own RBAC.
    conn
  end

  def call(%Plug.Conn{assigns: %{auth_type: :api_key, current_api_key: api_key, tenant_id: tenant_id}} = conn, permission) do
    with {:ok, user} <- UserManagement.get_user(tenant_id, api_key.ra_user_id),
         :ok <- UserManagement.authorize(user.role, permission) do
      conn
    else
      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(403, Jason.encode!(%{error: "forbidden"}))
        |> halt()
    end
  end

  def call(conn, _permission) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(403, Jason.encode!(%{error: "forbidden"}))
    |> halt()
  end
end
