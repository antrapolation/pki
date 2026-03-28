defmodule PkiRaPortal.RaEngineClient.ErrorMock do
  @moduledoc """
  Error-returning mock for testing error handling paths in LiveViews.
  All mutating operations return {:error, reason}.
  Read operations still succeed so mount/rendering works.
  """

  @behaviour PkiRaPortal.RaEngineClient

  # Read operations succeed (needed for mount)
  @impl true
  def list_users, do: PkiRaPortal.RaEngineClient.Mock.list_users()

  @impl true
  def list_csrs(filters), do: PkiRaPortal.RaEngineClient.Mock.list_csrs(filters)

  @impl true
  def get_csr(id), do: PkiRaPortal.RaEngineClient.Mock.get_csr(id)

  @impl true
  def list_cert_profiles, do: PkiRaPortal.RaEngineClient.Mock.list_cert_profiles()

  @impl true
  def list_service_configs, do: PkiRaPortal.RaEngineClient.Mock.list_service_configs()

  @impl true
  def list_api_keys(filters), do: PkiRaPortal.RaEngineClient.Mock.list_api_keys(filters)

  # Mutating operations return errors
  @impl true
  def create_user(_attrs), do: {:error, :permission_denied}

  @impl true
  def delete_user(_id), do: {:error, :not_found}

  @impl true
  def approve_csr(_id, _meta), do: {:error, :csr_already_processed}

  @impl true
  def reject_csr(_id, _reason, _meta), do: {:error, :csr_already_processed}

  @impl true
  def create_cert_profile(_attrs), do: {:error, :validation_failed}

  @impl true
  def update_cert_profile(_id, _attrs), do: {:error, :not_found}

  @impl true
  def delete_cert_profile(_id), do: {:error, :in_use}

  @impl true
  def configure_service(_attrs), do: {:error, :configuration_failed}

  @impl true
  def create_api_key(_attrs), do: {:error, :limit_exceeded}

  @impl true
  def revoke_api_key(_id), do: {:error, :already_revoked}

  @impl true
  def authenticate(username, _password), do: {:ok, %{id: "1", username: username, role: "ra_admin", display_name: "Error Mock Admin"}}

  @impl true
  def authenticate_with_session(username, _password) do
    user = %{id: "1", username: username, role: "ra_admin", display_name: "Error Mock Admin"}
    {:ok, user, %{session_key: "mock_key", session_salt: "mock_salt"}}
  end

  @impl true
  def register_user(_attrs), do: {:error, :registration_disabled}

  @impl true
  def needs_setup?, do: false
end
