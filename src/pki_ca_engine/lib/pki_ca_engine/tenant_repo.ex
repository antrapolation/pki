defmodule PkiCaEngine.TenantRepo do
  @moduledoc """
  Resolves the correct Ecto Repo for a tenant.
  Falls back to PkiCaEngine.Repo when no tenant context is provided (nil).
  """

  def ca_repo(nil), do: PkiCaEngine.Repo
  def ca_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{ca_repo: repo}} -> repo
      {:error, :not_found} -> PkiCaEngine.Repo
    end
  end

  def audit_repo(nil), do: PkiCaEngine.Repo
  def audit_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{audit_repo: repo}} -> repo
      {:error, :not_found} -> PkiCaEngine.Repo
    end
  end
end
