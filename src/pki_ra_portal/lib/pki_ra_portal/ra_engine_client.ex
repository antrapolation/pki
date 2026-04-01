defmodule PkiRaPortal.RaEngineClient do
  @moduledoc """
  Behaviour and delegating client for communicating with the RA engine.

  The implementation is configurable via application env:
    config :pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.Mock

  Defaults to Mock in dev/test; swap to an RPC implementation for prod.

  All authenticated endpoints accept an optional `opts` keyword list.
  Pass `tenant_id: "..."` to include the X-Tenant-ID header in requests.
  """

  @callback list_users(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback create_user(map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback create_user(map(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback delete_user(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_csrs(keyword(), keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback get_csr(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback approve_csr(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback reject_csr(String.t(), binary(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_cert_profiles(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback create_cert_profile(map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback update_cert_profile(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback delete_cert_profile(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_service_configs(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback configure_service(map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_api_keys(keyword(), keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback create_api_key(map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback revoke_api_key(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_ra_instances(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback create_ra_instance(map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback available_issuer_keys(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback authenticate(String.t(), String.t()) :: {:ok, map()} | {:error, :invalid_credentials}
  @callback authenticate_with_session(String.t(), String.t()) :: {:ok, map(), map()} | {:error, term()}
  @callback register_user(map()) :: {:ok, map()} | {:error, term()}
  @callback needs_setup?() :: boolean()
  @callback needs_setup?(String.t()) :: boolean()
  @callback get_user_by_username(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback reset_password(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  @callback update_user_profile(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback verify_and_change_password(String.t(), String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_portal_users(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback create_portal_user(map(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback suspend_user_role(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback activate_user_role(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback delete_user_role(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback reset_user_password(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback list_audit_events(keyword(), keyword()) :: {:ok, [map()]} | {:error, term()}

  defp impl,
    do: Application.get_env(:pki_ra_portal, :ra_engine_client, PkiRaPortal.RaEngineClient.Mock)

  def list_users(opts \\ []), do: impl().list_users(opts)
  def create_user(attrs, opts \\ []), do: impl().create_user(attrs, opts)
  def create_user(attrs, admin_context, opts), do: impl().create_user(attrs, admin_context, opts)
  def delete_user(id, opts \\ []), do: impl().delete_user(id, opts)
  def list_csrs(filters \\ [], opts \\ []), do: impl().list_csrs(filters, opts)
  def get_csr(id, opts \\ []), do: impl().get_csr(id, opts)
  def approve_csr(id, meta \\ %{}, opts \\ []), do: impl().approve_csr(id, meta, opts)
  def reject_csr(id, reason, meta \\ %{}, opts \\ []), do: impl().reject_csr(id, reason, meta, opts)
  def list_cert_profiles(opts \\ []), do: impl().list_cert_profiles(opts)
  def create_cert_profile(attrs, opts \\ []), do: impl().create_cert_profile(attrs, opts)
  def update_cert_profile(id, attrs, opts \\ []), do: impl().update_cert_profile(id, attrs, opts)
  def delete_cert_profile(id, opts \\ []), do: impl().delete_cert_profile(id, opts)
  def list_service_configs(opts \\ []), do: impl().list_service_configs(opts)
  def configure_service(attrs, opts \\ []), do: impl().configure_service(attrs, opts)
  def list_api_keys(filters \\ [], opts \\ []), do: impl().list_api_keys(filters, opts)
  def create_api_key(attrs, opts \\ []), do: impl().create_api_key(attrs, opts)
  def revoke_api_key(id, opts \\ []), do: impl().revoke_api_key(id, opts)
  def list_ra_instances(opts \\ []), do: impl().list_ra_instances(opts)
  def create_ra_instance(attrs, opts \\ []), do: impl().create_ra_instance(attrs, opts)
  def available_issuer_keys(opts \\ []), do: impl().available_issuer_keys(opts)
  def authenticate(username, password), do: impl().authenticate(username, password)
  def authenticate_with_session(username, password), do: impl().authenticate_with_session(username, password)
  def register_user(attrs), do: impl().register_user(attrs)
  def needs_setup?, do: impl().needs_setup?()
  def needs_setup?(tenant_id), do: impl().needs_setup?(tenant_id)
  def get_user_by_username(username, opts \\ []), do: impl().get_user_by_username(username, opts)
  def reset_password(user_id, new_password, opts \\ []), do: impl().reset_password(user_id, new_password, opts)
  def update_user_profile(user_id, attrs, opts \\ []), do: impl().update_user_profile(user_id, attrs, opts)
  def verify_and_change_password(user_id, current_password, new_password, opts \\ []), do: impl().verify_and_change_password(user_id, current_password, new_password, opts)
  def list_portal_users(opts \\ []), do: impl().list_portal_users(opts)
  def create_portal_user(attrs, opts \\ []), do: impl().create_portal_user(attrs, opts)
  def suspend_user_role(role_id, opts \\ []), do: impl().suspend_user_role(role_id, opts)
  def activate_user_role(role_id, opts \\ []), do: impl().activate_user_role(role_id, opts)
  def delete_user_role(role_id, opts \\ []), do: impl().delete_user_role(role_id, opts)
  def reset_user_password(user_id, opts \\ []), do: impl().reset_user_password(user_id, opts)
  def list_audit_events(filters, opts \\ []), do: impl().list_audit_events(filters, opts)
end
