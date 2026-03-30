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
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{ca_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        DynamicRepo

      {:error, :not_found} ->
        raise "Tenant #{tenant_id} not registered — engine not started"
    end
  end

  def audit_repo(nil), do: PkiCaEngine.Repo
  def audit_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{audit_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        DynamicRepo

      {:error, :not_found} ->
        raise "Tenant #{tenant_id} not registered — engine not started"
    end
  end
end
