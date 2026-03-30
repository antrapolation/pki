defmodule PkiRaEngine.RaInstanceManagement do
  @moduledoc """
  RA Instance Management — CRUD operations for RA instances.
  """

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.RaInstance

  @doc "Create a new RA instance."
  @spec create_ra_instance(String.t(), map()) :: {:ok, RaInstance.t()} | {:error, Ecto.Changeset.t()}
  def create_ra_instance(tenant_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    %RaInstance{}
    |> RaInstance.changeset(attrs)
    |> repo.insert()
  end

  @doc "Get an RA instance by ID."
  @spec get_ra_instance(String.t(), String.t()) :: {:ok, RaInstance.t()} | {:error, :not_found}
  def get_ra_instance(tenant_id, id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(RaInstance, id) do
      nil -> {:error, :not_found}
      ra -> {:ok, ra}
    end
  end

  @doc "List all RA instances."
  @spec list_ra_instances(String.t()) :: [RaInstance.t()]
  def list_ra_instances(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)
    repo.all(RaInstance)
  end

  @doc "Update the status of an RA instance."
  @spec update_status(String.t(), String.t(), String.t()) :: {:ok, RaInstance.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_status(tenant_id, id, new_status) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, ra} <- get_ra_instance(tenant_id, id) do
      ra
      |> RaInstance.changeset(%{status: new_status})
      |> repo.update()
    end
  end
end
