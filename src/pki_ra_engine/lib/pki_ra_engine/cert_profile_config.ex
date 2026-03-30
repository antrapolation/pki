defmodule PkiRaEngine.CertProfileConfig do
  @moduledoc """
  Certificate Profile Configuration — CRUD for cert profiles.
  """

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.CertProfile

  @doc "Create a new certificate profile."
  @spec create_profile(String.t(), map()) :: {:ok, CertProfile.t()} | {:error, Ecto.Changeset.t()}
  def create_profile(tenant_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    %CertProfile{}
    |> CertProfile.changeset(attrs)
    |> repo.insert()
  end

  @doc "Get a certificate profile by ID."
  @spec get_profile(String.t(), String.t()) :: {:ok, CertProfile.t()} | {:error, :not_found}
  def get_profile(tenant_id, id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(CertProfile, id) do
      nil -> {:error, :not_found}
      profile -> {:ok, profile}
    end
  end

  @doc "List all certificate profiles."
  @spec list_profiles(String.t()) :: [CertProfile.t()]
  def list_profiles(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)
    repo.all(CertProfile)
  end

  @doc "Update a certificate profile."
  @spec update_profile(String.t(), String.t(), map()) :: {:ok, CertProfile.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_profile(tenant_id, id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, profile} <- get_profile(tenant_id, id) do
      profile
      |> CertProfile.changeset(attrs)
      |> repo.update()
    end
  end

  @doc "Hard-delete a certificate profile."
  @spec delete_profile(String.t(), String.t()) :: {:ok, CertProfile.t()} | {:error, :not_found}
  def delete_profile(tenant_id, id) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, profile} <- get_profile(tenant_id, id) do
      repo.delete(profile)
    end
  end
end
