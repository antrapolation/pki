defmodule PkiCaPortal.CaEngineClient do
  @moduledoc """
  Behaviour and delegating client for communicating with the CA engine.

  The implementation is configurable via application env:
    config :pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock

  Defaults to Mock in dev/test; swap to an RPC implementation for prod.
  """

  @callback list_users(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback create_user(integer(), map()) :: {:ok, map()} | {:error, term()}
  @callback create_user(integer(), map(), map()) :: {:ok, map()} | {:error, term()}
  @callback get_user(String.t()) :: {:ok, map()} | {:error, term()}
  @callback delete_user(String.t()) :: {:ok, map()} | {:error, term()}
  @callback list_keystores(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback configure_keystore(integer(), map()) :: {:ok, map()} | {:error, term()}
  @callback list_issuer_keys(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback get_engine_status(integer()) :: {:ok, map()} | {:error, term()}
  @callback initiate_ceremony(integer(), map()) :: {:ok, map()} | {:error, term()}
  @callback list_ceremonies(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback list_ca_instances() :: {:ok, [map()]} | {:error, term()}
  @callback create_ca_instance(map()) :: {:ok, map()} | {:error, term()}
  @callback update_ca_instance(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback query_audit_log(keyword()) :: {:ok, [map()]} | {:error, term()}
  @callback authenticate(String.t(), String.t()) :: {:ok, map()} | {:error, :invalid_credentials}
  @callback authenticate_with_session(String.t(), String.t()) :: {:ok, map(), map()} | {:error, term()}
  @callback register_user(integer(), map()) :: {:ok, map()} | {:error, term()}
  @callback needs_setup?(integer()) :: boolean()
  @callback get_user_by_username(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  @callback reset_password(String.t(), String.t()) :: :ok | {:error, term()}

  defp impl,
    do: Application.get_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock)

  def list_users(ca_instance_id), do: impl().list_users(ca_instance_id)
  def create_user(ca_instance_id, attrs), do: impl().create_user(ca_instance_id, attrs)
  def create_user(ca_instance_id, attrs, admin_context), do: impl().create_user(ca_instance_id, attrs, admin_context)
  def get_user(id), do: impl().get_user(id)
  def delete_user(id), do: impl().delete_user(id)
  def list_keystores(ca_instance_id), do: impl().list_keystores(ca_instance_id)
  def configure_keystore(ca_instance_id, attrs), do: impl().configure_keystore(ca_instance_id, attrs)
  def list_issuer_keys(ca_instance_id), do: impl().list_issuer_keys(ca_instance_id)
  def get_engine_status(ca_instance_id), do: impl().get_engine_status(ca_instance_id)
  def initiate_ceremony(ca_instance_id, params), do: impl().initiate_ceremony(ca_instance_id, params)
  def list_ceremonies(ca_instance_id), do: impl().list_ceremonies(ca_instance_id)
  def list_ca_instances(), do: impl().list_ca_instances()
  def create_ca_instance(attrs), do: impl().create_ca_instance(attrs)
  def update_ca_instance(id, attrs), do: impl().update_ca_instance(id, attrs)
  def query_audit_log(filters), do: impl().query_audit_log(filters)
  def authenticate(username, password), do: impl().authenticate(username, password)
  def authenticate_with_session(username, password), do: impl().authenticate_with_session(username, password)
  def register_user(ca_instance_id, attrs), do: impl().register_user(ca_instance_id, attrs)
  def needs_setup?(ca_instance_id), do: impl().needs_setup?(ca_instance_id)
  def get_user_by_username(username, ca_instance_id \\ "default"), do: impl().get_user_by_username(username, ca_instance_id)
  def reset_password(user_id, new_password), do: impl().reset_password(user_id, new_password)
end
