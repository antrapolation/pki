defmodule PkiRaEngine.TenantRepo do
  @moduledoc """
  Resolves the correct Ecto Repo for an RA tenant.
  Falls back to PkiRaEngine.Repo when no tenant context is provided (nil).
  """

  def ra_repo(nil), do: PkiRaEngine.Repo
  def ra_repo(tenant_id) do
    case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
      {:ok, %{ra_repo: repo}} -> repo
      {:error, :not_found} -> PkiRaEngine.Repo
    end
  end
end
