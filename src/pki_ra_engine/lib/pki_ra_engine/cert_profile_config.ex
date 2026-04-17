defmodule PkiRaEngine.CertProfileConfig do
  @moduledoc """
  Certificate profile configuration CRUD against Mnesia.

  Replaces the Ecto-based implementation. tenant_id is no longer needed
  since each BEAM node serves a single tenant.
  """

  alias PkiMnesia.{Repo, Structs.CertProfile}

  @doc "Create a new certificate profile."
  @spec create_profile(map()) :: {:ok, CertProfile.t()} | {:error, term()}
  def create_profile(attrs) do
    profile = CertProfile.new(attrs)
    Repo.insert(profile)
  end

  @doc "Get a certificate profile by ID."
  @spec get_profile(binary()) :: {:ok, CertProfile.t()} | {:error, :not_found}
  def get_profile(id) do
    case Repo.get(CertProfile, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, profile} -> {:ok, profile}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "List active certificate profiles (excludes archived). Optionally filter by ra_instance_id."
  @spec list_profiles(binary() | nil) :: {:ok, [CertProfile.t()]} | {:error, term()}
  def list_profiles(ra_instance_id \\ nil) do
    if ra_instance_id do
      Repo.where(CertProfile, fn p ->
        p.ra_instance_id == ra_instance_id and p.status != "archived"
      end)
    else
      Repo.where(CertProfile, fn p -> p.status != "archived" end)
    end
  end

  @doc "List all certificate profiles including archived."
  @spec list_all_profiles() :: {:ok, [CertProfile.t()]} | {:error, term()}
  def list_all_profiles do
    Repo.all(CertProfile)
  end

  @doc "Update a certificate profile."
  @spec update_profile(binary(), map()) :: {:ok, CertProfile.t()} | {:error, :not_found | term()}
  def update_profile(id, changes) do
    case Repo.get(CertProfile, id) do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, profile} ->
        Repo.update(profile, Map.put(changes, :updated_at, DateTime.utc_now() |> DateTime.truncate(:second)))

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Delete a certificate profile (hard delete from Mnesia)."
  @spec delete_profile(binary()) :: {:ok, binary()} | {:error, term()}
  def delete_profile(id) do
    Repo.delete(CertProfile, id)
  end
end
