defmodule PkiCaEngine.TenantRepo do
  @moduledoc """
  Resolves the correct Ecto Repo for a tenant.
  Falls back to PkiCaEngine.Repo when no tenant context is provided (nil).
  Raises when a non-nil tenant_id is not found in the registry.

  For dynamic repos (multi-tenant), uses put_dynamic_repo to route
  DynamicRepo to the correct named process, then returns DynamicRepo.
  """

  alias PkiPlatformEngine.DynamicRepo

  def ca_repo(nil), do: PkiCaEngine.Repo
  def ca_repo(tenant_id) do
    case lookup_or_start(tenant_id) do
      {:ok, %{ca_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        DynamicRepo

      {:error, reason} ->
        raise "Tenant #{tenant_id} engine not available: #{inspect(reason)}"
    end
  end

  def audit_repo(nil), do: PkiCaEngine.Repo
  def audit_repo(tenant_id) do
    case lookup_or_start(tenant_id) do
      {:ok, %{audit_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        DynamicRepo

      {:error, reason} ->
        raise "Tenant #{tenant_id} engine not available: #{inspect(reason)}"
    end
  end

  defp lookup_or_start(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, _refs} = ok ->
        ok

      {:error, :not_found} ->
        case PkiPlatformEngine.Provisioner.get_tenant(tenant_id) do
          %{status: "active"} = tenant ->
            case PkiPlatformEngine.TenantSupervisor.start_tenant(tenant) do
              {:ok, _pid} -> PkiPlatformEngine.TenantRegistry.lookup(tenant_id)
              {:error, reason} -> {:error, {:engine_start_failed, reason}}
            end

          %{status: status} ->
            {:error, {:tenant_not_active, status}}

          nil ->
            {:error, :tenant_not_found}
        end
    end
  end
end
