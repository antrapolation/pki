defmodule PkiRaEngine.ServiceConfig do
  @moduledoc """
  Service configuration CRUD against Mnesia. Upsert by `service_type`.

  The embedded URL + port become CDP / OCSP / TSA extensions on
  issued certificates. One row per service_type per tenant.

  Replaces the Ecto-based implementation. tenant_id is no longer needed
  since each BEAM node serves a single tenant.
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.ServiceConfig, as: ServiceConfigStruct

  @service_types ~w(
    csr_web crl ldap ocsp ocsp_responder crl_distribution tsa
  )

  @doc "List valid `service_type` values."
  def service_types, do: @service_types

  @doc "Create or upsert a service configuration by service_type."
  @spec configure_service(map()) :: {:ok, ServiceConfigStruct.t()} | {:error, term()}
  def configure_service(attrs) do
    service_type = Map.get(attrs, :service_type) || Map.get(attrs, "service_type")

    cond do
      is_nil(service_type) ->
        {:error, :service_type_required}

      service_type not in @service_types ->
        {:error, :invalid_service_type}

      true ->
        case get_service_config(service_type) do
          {:ok, existing} ->
            Repo.update(existing, build_update(attrs))

          {:error, :not_found} ->
            attrs
            |> normalize_attrs()
            |> ServiceConfigStruct.new()
            |> Repo.insert()
        end
    end
  end

  @doc "Get a service configuration by service_type."
  @spec get_service_config(String.t()) :: {:ok, ServiceConfigStruct.t()} | {:error, :not_found}
  def get_service_config(service_type) do
    case Repo.where(ServiceConfigStruct, fn c -> c.service_type == service_type end) do
      {:ok, [config | _]} -> {:ok, config}
      {:ok, []} -> {:error, :not_found}
      {:error, _} = err -> err
    end
  end

  @doc "List all service configurations."
  @spec list_service_configs() :: [ServiceConfigStruct.t()]
  def list_service_configs do
    case Repo.all(ServiceConfigStruct) do
      {:ok, list} -> list
      _ -> []
    end
  end

  @doc "Update a service configuration by service_type."
  @spec update_service_config(String.t(), map()) ::
          {:ok, ServiceConfigStruct.t()} | {:error, :not_found | term()}
  def update_service_config(service_type, attrs) do
    with {:ok, config} <- get_service_config(service_type) do
      Repo.update(config, build_update(attrs))
    end
  end

  @doc "Delete a service configuration by service_type."
  @spec delete_service_config(String.t()) :: {:ok, binary()} | {:error, :not_found | term()}
  def delete_service_config(service_type) do
    with {:ok, config} <- get_service_config(service_type) do
      Repo.delete(ServiceConfigStruct, config.id)
    end
  end

  # --- Deprecated 2-arity wrappers (legacy callers before tenant_id dropped) ---

  @doc false
  def configure_service(_tenant_id, attrs), do: configure_service(attrs)

  @doc false
  def list_service_configs(_tenant_id), do: list_service_configs()

  @doc false
  def get_service_config(_tenant_id, service_type), do: get_service_config(service_type)

  @doc false
  def update_service_config(_tenant_id, service_type, attrs),
    do: update_service_config(service_type, attrs)

  @doc false
  def delete_service_config(_tenant_id, service_type), do: delete_service_config(service_type)

  defp normalize_attrs(attrs) do
    %{
      service_type: Map.get(attrs, :service_type) || Map.get(attrs, "service_type"),
      url: Map.get(attrs, :url) || Map.get(attrs, "url"),
      port: Map.get(attrs, :port) || Map.get(attrs, "port"),
      status: Map.get(attrs, :status) || Map.get(attrs, "status", "active")
    }
  end

  defp build_update(attrs) do
    attrs
    |> Map.take([:url, :port, :status, "url", "port", "status"])
    |> Enum.reduce(%{}, fn
      {k, v}, acc when is_atom(k) -> Map.put(acc, k, v)
      {k, v}, acc when is_binary(k) -> Map.put(acc, String.to_existing_atom(k), v)
    end)
    |> Map.put(:updated_at, DateTime.utc_now() |> DateTime.truncate(:second))
  end
end
