defmodule PkiCaEngine.KeystoreManagement do
  @moduledoc """
  Dynamic search and configuration of private keystores.

  Software keystore is activated by default. Key Managers select and
  configure the private keystore for each CA instance.
  """

  import Ecto.Query

  alias PkiCaEngine.Schema.Keystore
  alias PkiCaEngine.TenantRepo

  @provider_map %{
    "software" => "StrapSoftPrivKeyStoreProvider",
    "hsm" => "StrapSofthsmPrivKeyStoreProvider"
  }

  @doc """
  Creates a keystore configuration for a CA instance.
  """
  @spec configure_keystore(String.t(), String.t(), map()) :: {:ok, Keystore.t()} | {:error, term()}
  def configure_keystore(tenant_id, ca_instance_id, attrs) do
    repo = TenantRepo.ca_repo(tenant_id)
    type = attrs[:type] || attrs["type"]
    attrs = Map.put(attrs, :ca_instance_id, ca_instance_id)

    with {:ok, attrs} <- resolve_hsm_config(type, tenant_id, attrs) do
      %Keystore{}
      |> Keystore.changeset(attrs)
      |> repo.insert()
    end
  end

  defp resolve_hsm_config("hsm", tenant_id, attrs) do
    hsm_device_id = attrs[:hsm_device_id] || attrs["hsm_device_id"]

    case PkiPlatformEngine.HsmManagement.get_device_for_tenant(tenant_id, hsm_device_id) do
      {:ok, device} ->
        config = Keystore.encode_config(%{
          "hsm_device_id" => device.id,
          "pkcs11_lib_path" => device.pkcs11_lib_path,
          "slot_id" => device.slot_id,
          "label" => device.label
        })

        {:ok,
         attrs
         |> Map.put(:config, config)
         |> Map.put(:provider_name, device.label)}

      {:error, _} ->
        {:error, :hsm_device_not_found}
    end
  end
  defp resolve_hsm_config(_, _tenant_id, attrs), do: {:ok, attrs}

  @doc """
  Lists all keystores for a CA instance.
  """
  @spec list_keystores(String.t(), String.t() | nil) :: [Keystore.t()]
  def list_keystores(tenant_id, ca_instance_id \\ nil)
  def list_keystores(tenant_id, nil) do
    repo = TenantRepo.ca_repo(tenant_id)
    repo.all(Keystore)
  end
  def list_keystores(tenant_id, ca_instance_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    from(k in Keystore, where: k.ca_instance_id == ^ca_instance_id)
    |> repo.all()
  end

  @doc """
  Gets a keystore by ID.
  """
  @spec get_keystore(String.t(), String.t()) :: {:ok, Keystore.t()} | {:error, :not_found}
  def get_keystore(tenant_id, id) do
    repo = TenantRepo.ca_repo(tenant_id)
    case repo.get(Keystore, id) do
      nil -> {:error, :not_found}
      keystore -> {:ok, keystore}
    end
  end

  @doc "Gets a keystore by ID with decoded config map."
  def get_keystore_with_config(tenant_id, id) do
    case get_keystore(tenant_id, id) do
      {:ok, keystore} -> {:ok, keystore, Keystore.decode_config(keystore.config)}
      error -> error
    end
  end

  @doc """
  Updates a keystore's config or status.
  """
  @spec update_keystore(String.t(), String.t(), map()) :: {:ok, Keystore.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_keystore(tenant_id, id, attrs) do
    repo = TenantRepo.ca_repo(tenant_id)
    case repo.get(Keystore, id) do
      nil ->
        {:error, :not_found}

      keystore ->
        keystore
        |> Keystore.update_changeset(attrs)
        |> repo.update()
    end
  end

  @doc """
  Returns only active keystores for a CA instance.
  """
  @spec available_keystores(String.t(), String.t()) :: [Keystore.t()]
  def available_keystores(tenant_id, ca_instance_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    from(k in Keystore,
      where: k.ca_instance_id == ^ca_instance_id and k.status == "active"
    )
    |> repo.all()
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
