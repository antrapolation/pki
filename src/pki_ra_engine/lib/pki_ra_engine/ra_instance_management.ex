defmodule PkiRaEngine.RaInstanceManagement do
  @moduledoc """
  RA Instance Management — CRUD against Mnesia.

  Rewritten from Ecto/TenantRepo. tenant_id is no longer needed since
  each BEAM node serves a single tenant.
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.RaInstance

  @valid_statuses ~w(active inactive suspended)

  @doc "Create a new RA instance."
  @spec create_ra_instance(map()) :: {:ok, RaInstance.t()} | {:error, term()}
  def create_ra_instance(attrs) do
    name = Map.get(attrs, :name) || Map.get(attrs, "name")

    case name && String.trim(to_string(name)) do
      nil -> {:error, :name_required}
      "" -> {:error, :name_required}
      trimmed ->
        ra = RaInstance.new(Map.put(attrs, :name, trimmed))
        Repo.insert(ra)
    end
  end

  @doc "Get an RA instance by ID."
  @spec get_ra_instance(binary()) :: {:ok, RaInstance.t()} | {:error, :not_found}
  def get_ra_instance(id) do
    case Repo.get(RaInstance, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ra} -> {:ok, ra}
      {:error, _} = err -> err
    end
  end

  @doc "List all RA instances."
  @spec list_ra_instances() :: [RaInstance.t()]
  def list_ra_instances do
    case Repo.all(RaInstance) do
      {:ok, list} -> list
      _ -> []
    end
  end

  @doc "Update the status of an RA instance."
  @spec update_status(binary(), String.t()) ::
          {:ok, RaInstance.t()} | {:error, :not_found | :invalid_status | term()}
  def update_status(id, new_status) when new_status in @valid_statuses do
    with {:ok, ra} <- get_ra_instance(id) do
      Repo.update(ra, %{
        status: new_status,
        updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
    end
  end

  def update_status(_id, _bad), do: {:error, :invalid_status}

  # --- Deprecated 2-arity/3-arity wrappers for legacy callers ---

  @doc false
  def create_ra_instance(_tenant_id, attrs), do: create_ra_instance(attrs)

  @doc false
  def get_ra_instance(_tenant_id, id), do: get_ra_instance(id)

  @doc false
  def list_ra_instances(_tenant_id), do: list_ra_instances()

  @doc false
  def update_status(_tenant_id, id, new_status), do: update_status(id, new_status)
end
