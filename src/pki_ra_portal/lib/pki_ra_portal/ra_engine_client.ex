defmodule PkiRaPortal.RaEngineClient do
  @moduledoc """
  Behaviour and delegating client for communicating with the RA engine.

  The implementation is configurable via application env:
    config :pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.Mock

  Defaults to Mock in dev/test; swap to an RPC implementation for prod.
  """

  @callback list_users() :: {:ok, [map()]} | {:error, term()}
  @callback create_user(map()) :: {:ok, map()} | {:error, term()}
  @callback create_user(map(), map()) :: {:ok, map()} | {:error, term()}
  @callback delete_user(String.t()) :: {:ok, map()} | {:error, term()}
  @callback list_csrs(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback get_csr(String.t()) :: {:ok, map()} | {:error, term()}
  @callback approve_csr(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback reject_csr(String.t(), binary(), map()) :: {:ok, map()} | {:error, term()}
  @callback list_cert_profiles() :: {:ok, [map()]} | {:error, term()}
  @callback create_cert_profile(map()) :: {:ok, map()} | {:error, term()}
  @callback update_cert_profile(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback delete_cert_profile(String.t()) :: {:ok, map()} | {:error, term()}
  @callback list_service_configs() :: {:ok, [map()]} | {:error, term()}
  @callback configure_service(map()) :: {:ok, map()} | {:error, term()}
  @callback list_api_keys(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback create_api_key(map()) :: {:ok, map()} | {:error, term()}
  @callback revoke_api_key(String.t()) :: {:ok, map()} | {:error, term()}
  @callback list_ra_instances() :: {:ok, [map()]} | {:error, term()}
  @callback create_ra_instance(map()) :: {:ok, map()} | {:error, term()}
  @callback available_issuer_keys() :: {:ok, [map()]} | {:error, term()}
  @callback authenticate(String.t(), String.t()) :: {:ok, map()} | {:error, :invalid_credentials}
  @callback authenticate_with_session(String.t(), String.t()) :: {:ok, map(), map()} | {:error, term()}
  @callback register_user(map()) :: {:ok, map()} | {:error, term()}
  @callback needs_setup?() :: boolean()
  @callback needs_setup?(String.t()) :: boolean()
  @callback get_user_by_username(String.t()) :: {:ok, map()} | {:error, term()}

  defp impl,
    do: Application.get_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.Mock)

  def list_users, do: impl().list_users()
  def create_user(attrs), do: impl().create_user(attrs)
  def create_user(attrs, admin_context), do: impl().create_user(attrs, admin_context)
  def delete_user(id), do: impl().delete_user(id)
  def list_csrs(filters \\ []), do: impl().list_csrs(filters)
  def get_csr(id), do: impl().get_csr(id)
  def approve_csr(id, meta \\ %{}), do: impl().approve_csr(id, meta)
  def reject_csr(id, reason, meta \\ %{}), do: impl().reject_csr(id, reason, meta)
  def list_cert_profiles, do: impl().list_cert_profiles()
  def create_cert_profile(attrs), do: impl().create_cert_profile(attrs)
  def update_cert_profile(id, attrs), do: impl().update_cert_profile(id, attrs)
  def delete_cert_profile(id), do: impl().delete_cert_profile(id)
  def list_service_configs, do: impl().list_service_configs()
  def configure_service(attrs), do: impl().configure_service(attrs)
  def list_api_keys(filters \\ []), do: impl().list_api_keys(filters)
  def create_api_key(attrs), do: impl().create_api_key(attrs)
  def revoke_api_key(id), do: impl().revoke_api_key(id)
  def list_ra_instances, do: impl().list_ra_instances()
  def create_ra_instance(attrs), do: impl().create_ra_instance(attrs)
  def available_issuer_keys, do: impl().available_issuer_keys()
  def authenticate(username, password), do: impl().authenticate(username, password)
  def authenticate_with_session(username, password), do: impl().authenticate_with_session(username, password)
  def register_user(attrs), do: impl().register_user(attrs)
  def needs_setup?, do: impl().needs_setup?()
  def needs_setup?(tenant_id), do: impl().needs_setup?(tenant_id)
  def get_user_by_username(username), do: impl().get_user_by_username(username)
end
