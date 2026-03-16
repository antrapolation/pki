defmodule PkiRaEngine.ServiceConfig do
  @moduledoc """
  Service Configuration — CRUD for Web/CRL/LDAP/OCSP service configs.
  Supports upsert by service_type.
  """

  alias PkiRaEngine.Repo
  alias PkiRaEngine.Schema.ServiceConfig, as: ServiceConfigSchema

  @doc "Create or upsert a service configuration by service_type."
  @spec configure_service(map()) :: {:ok, ServiceConfigSchema.t()} | {:error, Ecto.Changeset.t()}
  def configure_service(attrs) do
    service_type = Map.get(attrs, :service_type) || Map.get(attrs, "service_type")

    case service_type && Repo.get_by(ServiceConfigSchema, service_type: service_type) do
      nil ->
        %ServiceConfigSchema{}
        |> ServiceConfigSchema.changeset(attrs)
        |> Repo.insert()

      existing ->
        existing
        |> ServiceConfigSchema.changeset(attrs)
        |> Repo.update()
    end
  end

  @doc "Get a service configuration by service_type string."
  @spec get_service_config(String.t()) :: {:ok, ServiceConfigSchema.t()} | {:error, :not_found}
  def get_service_config(service_type) do
    case Repo.get_by(ServiceConfigSchema, service_type: service_type) do
      nil -> {:error, :not_found}
      config -> {:ok, config}
    end
  end

  @doc "List all service configurations."
  @spec list_service_configs() :: [ServiceConfigSchema.t()]
  def list_service_configs do
    Repo.all(ServiceConfigSchema)
  end

  @doc "Update a service configuration by service_type."
  @spec update_service_config(String.t(), map()) ::
          {:ok, ServiceConfigSchema.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_service_config(service_type, attrs) do
    with {:ok, config} <- get_service_config(service_type) do
      config
      |> ServiceConfigSchema.changeset(attrs)
      |> Repo.update()
    end
  end

  @doc "Delete a service configuration by service_type."
  @spec delete_service_config(String.t()) :: {:ok, ServiceConfigSchema.t()} | {:error, :not_found}
  def delete_service_config(service_type) do
    with {:ok, config} <- get_service_config(service_type) do
      Repo.delete(config)
    end
  end
end
