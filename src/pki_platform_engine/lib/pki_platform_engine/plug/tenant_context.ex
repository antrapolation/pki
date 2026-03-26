defmodule PkiPlatformEngine.Plug.TenantContext do
  @moduledoc """
  Plug that resolves the current tenant from the request context
  and stores it in conn.assigns.

  Tries these sources in order:
  1. Session (tenant_id)
  2. X-Tenant-ID header
  3. Subdomain

  If no tenant is resolved, the request continues without tenant context
  (for public/unauthenticated endpoints).
  """

  import Plug.Conn
  alias PkiPlatformEngine.Resolver

  def init(opts), do: opts

  def call(conn, _opts) do
    case resolve_tenant(conn) do
      {:ok, tenant} ->
        assign(conn, :current_tenant, tenant)

      {:error, :tenant_suspended} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(403, Jason.encode!(%{error: "tenant_suspended"}))
        |> halt()

      {:error, _} ->
        assign(conn, :current_tenant, nil)
    end
  end

  defp resolve_tenant(conn) do
    with {:error, _} <- Resolver.resolve_from_session(conn.private[:plug_session] || %{}),
         {:error, _} <- Resolver.resolve_from_header(conn),
         {:error, _} <- Resolver.resolve_from_subdomain(conn.host) do
      {:error, :no_tenant}
    end
  end
end
