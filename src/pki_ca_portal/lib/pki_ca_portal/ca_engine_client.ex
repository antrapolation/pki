defmodule PkiCaPortal.CaEngineClient do
  @moduledoc """
  Behaviour and delegating client for communicating with the CA engine.

  The implementation is configurable via application env:
    config :pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock

  Defaults to Mock in dev/test; swap to an RPC implementation for prod.
  """

  @callback list_users(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback create_user(integer(), map()) :: {:ok, map()} | {:error, term()}
  @callback get_user(integer()) :: {:ok, map()} | {:error, term()}
  @callback delete_user(integer()) :: {:ok, map()} | {:error, term()}
  @callback list_keystores(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback configure_keystore(integer(), map()) :: {:ok, map()} | {:error, term()}
  @callback list_issuer_keys(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback get_engine_status(integer()) :: {:ok, map()} | {:error, term()}
  @callback initiate_ceremony(integer(), map()) :: {:ok, map()} | {:error, term()}
  @callback list_ceremonies(integer()) :: {:ok, [map()]} | {:error, term()}
  @callback query_audit_log(keyword()) :: {:ok, [map()]} | {:error, term()}

  defp impl,
    do: Application.get_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock)

  def list_users(ca_instance_id), do: impl().list_users(ca_instance_id)
  def create_user(ca_instance_id, attrs), do: impl().create_user(ca_instance_id, attrs)
  def get_user(id), do: impl().get_user(id)
  def delete_user(id), do: impl().delete_user(id)
  def list_keystores(ca_instance_id), do: impl().list_keystores(ca_instance_id)
  def configure_keystore(ca_instance_id, attrs), do: impl().configure_keystore(ca_instance_id, attrs)
  def list_issuer_keys(ca_instance_id), do: impl().list_issuer_keys(ca_instance_id)
  def get_engine_status(ca_instance_id), do: impl().get_engine_status(ca_instance_id)
  def initiate_ceremony(ca_instance_id, params), do: impl().initiate_ceremony(ca_instance_id, params)
  def list_ceremonies(ca_instance_id), do: impl().list_ceremonies(ca_instance_id)
  def query_audit_log(filters), do: impl().query_audit_log(filters)
end
