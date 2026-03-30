defmodule PkiCaPortal.CaEngineClient.ErrorMock do
  @moduledoc """
  Error-returning mock for testing error handling paths in LiveViews.
  All mutating operations return {:error, reason}.
  Read operations still succeed so mount/rendering works.
  """

  @behaviour PkiCaPortal.CaEngineClient

  # Read operations succeed (needed for mount)
  @impl true
  def list_users(_ca_instance_id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.list_users(1)

  @impl true
  def get_user(id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.get_user(id)

  @impl true
  def list_keystores(_ca_instance_id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.list_keystores(1)

  @impl true
  def list_issuer_keys(_ca_instance_id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.list_issuer_keys(1)

  @impl true
  def get_engine_status(_ca_instance_id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.get_engine_status(1)

  @impl true
  def list_ceremonies(_ca_instance_id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.list_ceremonies(1)

  @impl true
  def query_audit_log(filters, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.query_audit_log(filters)

  @impl true
  def list_ca_instances(_opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.list_ca_instances()

  @impl true
  def create_ca_instance(attrs, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.create_ca_instance(attrs)

  @impl true
  def update_ca_instance(id, attrs, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.update_ca_instance(id, attrs)

  # Auth operations delegate to main mock
  @impl true
  def authenticate(username, password, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.authenticate(username, password)

  @impl true
  def authenticate_with_session(username, password, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.authenticate_with_session(username, password)

  @impl true
  def register_user(ca_instance_id, attrs, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.register_user(ca_instance_id, attrs)

  @impl true
  def needs_setup?(ca_instance_id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.needs_setup?(ca_instance_id)

  @impl true
  def get_user_by_username(username, ca_instance_id, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.get_user_by_username(username, ca_instance_id)

  @impl true
  def reset_password(user_id, new_password, _opts \\ []), do: PkiCaPortal.CaEngineClient.Mock.reset_password(user_id, new_password)

  # Mutating operations return errors
  @impl true
  def create_user(_ca_instance_id, _attrs, _opts \\ []), do: {:error, :permission_denied}

  @impl true
  def create_user_with_admin(_ca_instance_id, _attrs, _admin_context, _opts \\ []), do: {:error, :permission_denied}

  @impl true
  def delete_user(_id, _opts \\ []), do: {:error, :not_found}

  @impl true
  def configure_keystore(_ca_instance_id, _attrs, _opts \\ []), do: {:error, :configuration_failed}

  @impl true
  def initiate_ceremony(_ca_instance_id, _params, _opts \\ []), do: {:error, :ceremony_in_progress}
end
