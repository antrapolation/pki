defmodule PkiRaEngine.RaInstanceManagement do
  @moduledoc """
  RA Instance Management — CRUD operations for RA instances.
  """

  alias PkiRaEngine.Repo
  alias PkiRaEngine.Schema.RaInstance

  @doc "Create a new RA instance."
  @spec create_ra_instance(map()) :: {:ok, RaInstance.t()} | {:error, Ecto.Changeset.t()}
  def create_ra_instance(attrs) do
    %RaInstance{}
    |> RaInstance.changeset(attrs)
    |> Repo.insert()
  end

  @doc "Get an RA instance by ID."
  @spec get_ra_instance(String.t()) :: {:ok, RaInstance.t()} | {:error, :not_found}
  def get_ra_instance(id) do
    case Repo.get(RaInstance, id) do
      nil -> {:error, :not_found}
      ra -> {:ok, ra}
    end
  end

  @doc "List all RA instances."
  @spec list_ra_instances() :: [RaInstance.t()]
  def list_ra_instances do
    Repo.all(RaInstance)
  end

  @doc "Update the status of an RA instance."
  @spec update_status(String.t(), String.t()) :: {:ok, RaInstance.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_status(id, new_status) do
    with {:ok, ra} <- get_ra_instance(id) do
      ra
      |> RaInstance.changeset(%{status: new_status})
      |> Repo.update()
    end
  end
end
