defmodule PkiRaEngine.CertProfileConfig do
  @moduledoc """
  Certificate Profile Configuration — CRUD for cert profiles.
  """

  alias PkiRaEngine.Repo
  alias PkiRaEngine.Schema.CertProfile

  @doc "Create a new certificate profile."
  @spec create_profile(map()) :: {:ok, CertProfile.t()} | {:error, Ecto.Changeset.t()}
  def create_profile(attrs) do
    %CertProfile{}
    |> CertProfile.changeset(attrs)
    |> Repo.insert()
  end

  @doc "Get a certificate profile by ID."
  @spec get_profile(String.t()) :: {:ok, CertProfile.t()} | {:error, :not_found}
  def get_profile(id) do
    case Repo.get(CertProfile, id) do
      nil -> {:error, :not_found}
      profile -> {:ok, profile}
    end
  end

  @doc "List all certificate profiles."
  @spec list_profiles() :: [CertProfile.t()]
  def list_profiles do
    Repo.all(CertProfile)
  end

  @doc "Update a certificate profile."
  @spec update_profile(String.t(), map()) :: {:ok, CertProfile.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_profile(id, attrs) do
    with {:ok, profile} <- get_profile(id) do
      profile
      |> CertProfile.changeset(attrs)
      |> Repo.update()
    end
  end

  @doc "Hard-delete a certificate profile."
  @spec delete_profile(String.t()) :: {:ok, CertProfile.t()} | {:error, :not_found}
  def delete_profile(id) do
    with {:ok, profile} <- get_profile(id) do
      Repo.delete(profile)
    end
  end
end
