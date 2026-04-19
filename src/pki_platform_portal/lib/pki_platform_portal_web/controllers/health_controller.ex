defmodule PkiPlatformPortalWeb.HealthController do
  use PkiPlatformPortalWeb, :controller

  require Logger

  @erpc_timeout 5_000

  def show(conn, _params) do
    tenants = list_tenants_safe()

    tenant_health =
      Enum.map(tenants, fn tenant ->
        health = fetch_tenant_health(tenant)
        Map.merge(%{tenant_id: tenant.id, slug: tenant.slug, node: tenant.node}, health)
      end)

    overall_status =
      if Enum.all?(tenant_health, fn t -> Map.get(t, :status) == "healthy" end),
        do: "healthy",
        else: "degraded"

    payload = %{
      status: overall_status,
      node: node(),
      tenant_count: length(tenants),
      tenants: tenant_health
    }

    status_code = if overall_status == "healthy", do: 200, else: 503

    conn
    |> put_status(status_code)
    |> json(payload)
  end

  # -- Private helpers --

  defp list_tenants_safe do
    case Process.whereis(PkiPlatformEngine.TenantLifecycle) do
      nil -> []
      _pid -> PkiPlatformEngine.TenantLifecycle.list_tenants()
    end
  rescue
    _ -> []
  end

  defp fetch_tenant_health(%{node: node_name}) when is_atom(node_name) do
    case :erpc.call(node_name, PkiTenant.Health, :check, [], @erpc_timeout) do
      {:error, _} ->
        %{status: "unreachable", error: "erpc call failed"}

      health when is_map(health) ->
        health
    end
  rescue
    e ->
      Logger.warning("[health_controller] Failed to reach tenant node: #{inspect(e)}")
      %{status: "unreachable", error: inspect(e)}
  end

  defp fetch_tenant_health(_), do: %{status: "unreachable", error: "no node info"}
end
