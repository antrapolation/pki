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
    case lookup_or_start(tenant_id) do
      {:ok, %{ra_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        DynamicRepo

      {:error, reason} ->
        raise "Tenant #{tenant_id} engine not available: #{inspect(reason)}"
    end
  end

  @doc "Safe variant that returns {:ok, repo} or {:error, :tenant_not_found}."
  def ra_repo_safe(nil), do: {:ok, PkiRaEngine.Repo}
  def ra_repo_safe(tenant_id) do
    case lookup_or_start(tenant_id) do
      {:ok, %{ra_repo: name}} ->
        DynamicRepo.put_dynamic_repo(name)
        {:ok, DynamicRepo}

      {:error, _reason} ->
        {:error, :tenant_not_found}
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
