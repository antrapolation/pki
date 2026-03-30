defmodule PkiRaEngine.ServiceConfig do
  @moduledoc """
  Service Configuration — CRUD for Web/CRL/LDAP/OCSP service configs.
  Supports upsert by service_type.
  """

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.ServiceConfig, as: ServiceConfigSchema

  @doc "Create or upsert a service configuration by service_type."
  @spec configure_service(term(), map()) :: {:ok, ServiceConfigSchema.t()} | {:error, Ecto.Changeset.t()}
  def configure_service(tenant_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)
    service_type = Map.get(attrs, :service_type) || Map.get(attrs, "service_type")

    case service_type && repo.get_by(ServiceConfigSchema, service_type: service_type) do
      nil ->
        %ServiceConfigSchema{}
        |> ServiceConfigSchema.changeset(attrs)
        |> repo.insert()

      existing ->
        existing
        |> ServiceConfigSchema.changeset(attrs)
        |> repo.update()
    end
  end

  @doc "Get a service configuration by service_type string."
  @spec get_service_config(term(), String.t()) :: {:ok, ServiceConfigSchema.t()} | {:error, :not_found}
  def get_service_config(tenant_id, service_type) do
    repo = TenantRepo.ra_repo(tenant_id)
    case repo.get_by(ServiceConfigSchema, service_type: service_type) do
      nil -> {:error, :not_found}
      config -> {:ok, config}
    end
  end

  @doc "List all service configurations."
  @spec list_service_configs(term()) :: [ServiceConfigSchema.t()]
  def list_service_configs(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)
    repo.all(ServiceConfigSchema)
  end

  @doc "Update a service configuration by service_type."
  @spec update_service_config(term(), String.t(), map()) ::
          {:ok, ServiceConfigSchema.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_service_config(tenant_id, service_type, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)
    with {:ok, config} <- get_service_config(tenant_id, service_type) do
      config
      |> ServiceConfigSchema.changeset(attrs)
      |> repo.update()
    end
  end

  @doc "Delete a service configuration by service_type."
  @spec delete_service_config(term(), String.t()) :: {:ok, ServiceConfigSchema.t()} | {:error, :not_found}
  def delete_service_config(tenant_id, service_type) do
    repo = TenantRepo.ra_repo(tenant_id)
    with {:ok, config} <- get_service_config(tenant_id, service_type) do
      repo.delete(config)
    end
  end
end
