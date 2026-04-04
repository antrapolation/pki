defmodule PkiRaEngine.TenantRepo do
  @moduledoc """
  Resolves the correct Ecto Repo for an RA tenant.
  Falls back to PkiRaEngine.Repo when no tenant context is provided (nil).
  Raises when a non-nil tenant_id is not found in the registry.
  """

  alias PkiPlatformEngine.DynamicRepo

  @doc "Returns the repo module for the given tenant. Raises on unknown tenant."
  def ra_repo(nil), do: PkiRaEngine.Repo
  def ra_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{ra_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        DynamicRepo

      {:error, :not_found} ->
        raise "Tenant #{tenant_id} not registered — engine not started"
    end
  end

  @doc "Safe variant that returns {:ok, repo} or {:error, :tenant_not_found}."
  def ra_repo_safe(nil), do: {:ok, PkiRaEngine.Repo}
  def ra_repo_safe(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{ra_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        {:ok, DynamicRepo}

      {:error, :not_found} ->
        {:error, :tenant_not_found}
    end
  end
end
