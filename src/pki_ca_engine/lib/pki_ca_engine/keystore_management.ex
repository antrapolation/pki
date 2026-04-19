defmodule PkiCaEngine.KeystoreManagement do
  @moduledoc """
  Dynamic search and configuration of private keystores against
  Mnesia.

  Software keystore is activated by default. Key Managers select and
  configure the private keystore for each CA instance. HSM-backed
  keystores resolve their `config` from
  `PkiCaEngine.HsmDeviceManagement` at `configure_keystore/2` time.

  tenant_id is no longer needed since each BEAM node serves a single
  tenant.
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.Keystore

  @provider_map %{
    "software" => "StrapSoftPrivKeyStoreProvider",
    "hsm" => "StrapSofthsmPrivKeyStoreProvider"
  }

  @valid_types Map.keys(@provider_map)
  @valid_statuses ~w(active inactive)

  @doc "Create a keystore for a CA instance. Resolves HSM config at write time."
  @spec configure_keystore(binary(), map()) :: {:ok, Keystore.t()} | {:error, term()}
  def configure_keystore(ca_instance_id, attrs) do
    type = attrs[:type] || attrs["type"]

    cond do
      is_nil(ca_instance_id) or ca_instance_id == "" ->
        {:error, :ca_instance_required}

      type not in @valid_types ->
        {:error, :invalid_type}

      true ->
        with {:ok, config_attrs} <- resolve_hsm_config(type, attrs) do
          keystore =
            Keystore.new(%{
              ca_instance_id: ca_instance_id,
              type: type,
              config: config_attrs[:config] || config_attrs["config"] || %{},
              status: Map.get(attrs, :status, "active"),
              provider_name: config_attrs[:provider_name] || Map.get(@provider_map, type)
            })

          Repo.insert(keystore)
        end
    end
  end

  @doc "List all keystores, optionally filtered by ca_instance_id."
  @spec list_keystores(binary() | nil) :: [Keystore.t()]
  def list_keystores(ca_instance_id \\ nil)

  def list_keystores(nil) do
    case Repo.all(Keystore) do
      {:ok, list} -> list
      _ -> []
    end
  end

  def list_keystores(ca_instance_id) do
    case Repo.where(Keystore, fn k -> k.ca_instance_id == ca_instance_id end) do
      {:ok, list} -> list
      _ -> []
    end
  end

  @doc "Return only active keystores for a CA instance."
  @spec available_keystores(binary()) :: [Keystore.t()]
  def available_keystores(ca_instance_id) do
    case Repo.where(Keystore, fn k ->
           k.ca_instance_id == ca_instance_id and k.status == "active"
         end) do
      {:ok, list} -> list
      _ -> []
    end
  end

  @doc "Get a keystore by id."
  @spec get_keystore(binary()) :: {:ok, Keystore.t()} | {:error, :not_found}
  def get_keystore(id) do
    case Repo.get(Keystore, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, keystore} -> {:ok, keystore}
      {:error, _} = err -> err
    end
  end

  @doc "Get a keystore by id with its config map (already decoded on read)."
  def get_keystore_with_config(id) do
    case get_keystore(id) do
      {:ok, keystore} -> {:ok, keystore, Keystore.decode_config(keystore.config)}
      error -> error
    end
  end

  @doc "Update a keystore's config / status / provider_name."
  @spec update_keystore(binary(), map()) ::
          {:ok, Keystore.t()} | {:error, :not_found | :invalid_status | term()}
  def update_keystore(id, attrs) do
    with {:ok, keystore} <- get_keystore(id),
         :ok <- validate_status(attrs[:status] || attrs["status"]) do
      changes =
        attrs
        |> Map.take([:config, :status, :provider_name, "config", "status", "provider_name"])
        |> Enum.reduce(%{}, fn
          {k, v}, acc when is_atom(k) -> Map.put(acc, k, v)
          {k, v}, acc when is_binary(k) -> Map.put(acc, String.to_existing_atom(k), v)
        end)
        |> Map.put(:updated_at, DateTime.utc_now() |> DateTime.truncate(:second))

      Repo.update(keystore, changes)
    end
  end

  @doc "Map a keystore type string to its provider module name."
  @spec get_provider_module(String.t()) :: {:ok, String.t()} | {:error, :unknown_provider}
  def get_provider_module(type) do
    case Map.get(@provider_map, type) do
      nil -> {:error, :unknown_provider}
      module -> {:ok, module}
    end
  end

  # --- Deprecated 2-arity/3-arity wrappers for legacy callers ---

  @doc false
  def configure_keystore(_tenant_id, ca_instance_id, attrs),
    do: configure_keystore(ca_instance_id, attrs)

  @doc false
  def list_keystores(_tenant_id, ca_instance_id), do: list_keystores(ca_instance_id)

  @doc false
  def get_keystore(_tenant_id, id), do: get_keystore(id)

  @doc false
  def get_keystore_with_config(_tenant_id, id), do: get_keystore_with_config(id)

  @doc false
  def update_keystore(_tenant_id, id, attrs), do: update_keystore(id, attrs)

  @doc false
  def available_keystores(_tenant_id, ca_instance_id), do: available_keystores(ca_instance_id)

  # --- Private ---

  defp resolve_hsm_config("hsm", attrs) do
    hsm_device_id = attrs[:hsm_device_id] || attrs["hsm_device_id"]

    cond do
      is_nil(hsm_device_id) or hsm_device_id == "" ->
        {:ok,
         attrs
         |> Map.put_new(:config, %{})
         |> Map.put_new(:provider_name, Map.get(@provider_map, "hsm"))}

      true ->
        case PkiCaEngine.HsmDeviceManagement.get_device_for_tenant(
               PkiTenant.tenant_id(),
               hsm_device_id
             ) do
          {:ok, device} ->
            config = %{
              "hsm_device_id" => device.id,
              "pkcs11_lib_path" => device.pkcs11_lib_path,
              "slot_id" => device.slot_id,
              "label" => device.label
            }

            {:ok,
             attrs
             |> Map.put(:config, config)
             |> Map.put(:provider_name, Map.get(@provider_map, "hsm"))}

          {:error, _} ->
            {:error, :hsm_device_not_found}
        end
    end
  end

  defp resolve_hsm_config(_, attrs), do: {:ok, attrs}

  defp validate_status(nil), do: :ok
  defp validate_status(s) when s in @valid_statuses, do: :ok
  defp validate_status(_), do: {:error, :invalid_status}
end
