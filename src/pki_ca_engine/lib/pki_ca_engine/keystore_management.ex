defmodule PkiCaEngine.KeystoreManagement do
  @moduledoc """
  Dynamic search and configuration of private keystores.

  Software keystore is activated by default. Key Managers select and
  configure the private keystore for each CA instance.
  """

  import Ecto.Query

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.Keystore

  @provider_map %{
    "software" => "StrapSoftPrivKeyStoreProvider",
    "hsm" => "StrapSofthsmPrivKeyStoreProvider"
  }

  @doc """
  Creates a keystore configuration for a CA instance.
  """
  @spec configure_keystore(String.t(), map()) :: {:ok, Keystore.t()} | {:error, Ecto.Changeset.t()}
  def configure_keystore(ca_instance_id, attrs) do
    attrs = Map.put(attrs, :ca_instance_id, ca_instance_id)

    %Keystore{}
    |> Keystore.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists all keystores for a CA instance.
  """
  @spec list_keystores(String.t() | nil) :: [Keystore.t()]
  def list_keystores(nil), do: Repo.all(Keystore)
  def list_keystores(ca_instance_id) do
    from(k in Keystore, where: k.ca_instance_id == ^ca_instance_id)
    |> Repo.all()
  end

  @doc """
  Gets a keystore by ID.
  """
  @spec get_keystore(String.t()) :: {:ok, Keystore.t()} | {:error, :not_found}
  def get_keystore(id) do
    case Repo.get(Keystore, id) do
      nil -> {:error, :not_found}
      keystore -> {:ok, keystore}
    end
  end

  @doc """
  Updates a keystore's config or status.
  """
  @spec update_keystore(String.t(), map()) :: {:ok, Keystore.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_keystore(id, attrs) do
    case Repo.get(Keystore, id) do
      nil ->
        {:error, :not_found}

      keystore ->
        keystore
        |> Keystore.update_changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Returns only active keystores for a CA instance.
  """
  @spec available_keystores(String.t()) :: [Keystore.t()]
  def available_keystores(ca_instance_id) do
    from(k in Keystore,
      where: k.ca_instance_id == ^ca_instance_id and k.status == "active"
    )
    |> Repo.all()
  end

  @doc """
  Maps a keystore type to its provider module string.
  """
  @spec get_provider_module(String.t()) :: {:ok, String.t()} | {:error, :unknown_provider}
  def get_provider_module(type) do
    case Map.get(@provider_map, type) do
      nil -> {:error, :unknown_provider}
      module -> {:ok, module}
    end
  end
end
