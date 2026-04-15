defmodule PkiCaPortal.CaEngineClient do
  @moduledoc """
  Behaviour and delegating client for communicating with the CA engine.

  The implementation is configurable via application env:
    config :pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock

  Defaults to Mock in dev/test; swap to an RPC implementation for prod.

  All functions accept an optional `opts` keyword list as the last argument.
  When `tenant_id: <id>` is included, the X-Tenant-ID header is sent with the request.
  """

  @type opts :: [tenant_id: String.t()] | []

  @callback list_users(integer(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback create_user(integer(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback create_user_with_admin(integer(), map(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback get_user(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback delete_user(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_keystores(integer(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback configure_keystore(integer(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_issuer_keys(integer(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback get_engine_status(integer(), opts()) :: {:ok, map()} | {:error, term()}
  @callback initiate_ceremony(integer(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_ceremonies(integer(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback list_ca_instances(opts()) :: {:ok, [map()]} | {:error, term()}
  @callback create_ca_instance(map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback update_ca_instance(String.t(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback query_audit_log(keyword(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback authenticate(String.t(), String.t(), opts()) :: {:ok, map()} | {:error, :invalid_credentials}
  @callback authenticate_with_session(String.t(), String.t(), opts()) :: {:ok, map(), map()} | {:error, term()}
  @callback register_user(integer(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback needs_setup?(integer(), opts()) :: boolean()
  @callback get_user_by_username(String.t(), String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback reset_password(String.t(), String.t(), opts()) :: :ok | {:error, term()}
  @callback update_user_profile(String.t(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback verify_and_change_password(String.t(), String.t(), String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_portal_users(opts()) :: {:ok, [map()]} | {:error, term()}
  @callback create_portal_user(map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback suspend_user_role(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback activate_user_role(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback delete_user_role(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback reset_user_password(String.t(), opts()) :: :ok | {:error, term()}
  @callback resend_invitation(String.t(), opts()) :: :ok | {:error, term()}
  @callback list_hsm_devices(opts()) :: {:ok, [map()]} | {:error, term()}
  @callback register_hsm_device(map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback probe_hsm_device(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback deactivate_hsm_device(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_audit_events(keyword(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback get_ceremony(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback generate_ceremony_keypair(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback distribute_ceremony_shares(String.t(), binary(), [{String.t(), String.t()}], opts()) :: {:ok, integer()} | {:error, term()}
  @callback complete_ceremony_root(String.t(), binary(), String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback complete_ceremony_sub_ca(String.t(), binary(), opts()) :: {:ok, {map(), String.t()}} | {:error, term()}
  @callback cancel_ceremony(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback delete_ceremony(String.t(), opts()) :: :ok | {:error, term()}
  @callback get_issuer_key(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_threshold_shares(String.t(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback reconstruct_key(String.t(), [{String.t(), String.t()}], opts()) :: {:ok, binary()} | {:error, term()}
  @callback unlock_key(String.t(), [{String.t(), String.t()}], opts()) :: {:ok, :key_activated} | {:error, term()}
  @callback is_key_active?(String.t(), opts()) :: boolean()
  @callback sign_csr(String.t(), binary(), String.t(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback activate_issuer_key(String.t(), map(), opts()) :: {:ok, map()} | {:error, term()}
  @callback suspend_issuer_key(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback reactivate_issuer_key(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback retire_issuer_key(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback archive_issuer_key(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_certificates(String.t(), opts()) :: {:ok, [map()]} | {:error, term()}
  @callback get_certificate(String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback revoke_certificate(String.t(), String.t(), opts()) :: {:ok, map()} | {:error, term()}
  @callback list_active_ceremonies() :: {:ok, [map()]} | {:error, term()}
  @callback fail_ceremony(String.t(), String.t()) :: {:ok, map()} | {:error, term()}

  defp impl,
    do: Application.get_env(:pki_ca_portal, :ca_engine_client, PkiCaPortal.CaEngineClient.Mock)

  def list_users(ca_instance_id, opts \\ []), do: impl().list_users(ca_instance_id, opts)
  def create_user(ca_instance_id, attrs, opts \\ []), do: impl().create_user(ca_instance_id, attrs, opts)
  def create_user_with_admin(ca_instance_id, attrs, admin_context, opts \\ []), do: impl().create_user_with_admin(ca_instance_id, attrs, admin_context, opts)
  def get_user(id, opts \\ []), do: impl().get_user(id, opts)
  def delete_user(id, opts \\ []), do: impl().delete_user(id, opts)
  def list_keystores(ca_instance_id, opts \\ []), do: impl().list_keystores(ca_instance_id, opts)
  def configure_keystore(ca_instance_id, attrs, opts \\ []), do: impl().configure_keystore(ca_instance_id, attrs, opts)
  def list_issuer_keys(ca_instance_id, opts \\ []), do: impl().list_issuer_keys(ca_instance_id, opts)
  def get_engine_status(ca_instance_id, opts \\ []), do: impl().get_engine_status(ca_instance_id, opts)
  def initiate_ceremony(ca_instance_id, params, opts \\ []), do: impl().initiate_ceremony(ca_instance_id, params, opts)
  def list_ceremonies(ca_instance_id, opts \\ []), do: impl().list_ceremonies(ca_instance_id, opts)
  def list_ca_instances(opts \\ []), do: impl().list_ca_instances(opts)
  def create_ca_instance(attrs, opts \\ []), do: impl().create_ca_instance(attrs, opts)
  def update_ca_instance(id, attrs, opts \\ []), do: impl().update_ca_instance(id, attrs, opts)
  def query_audit_log(filters, opts \\ []), do: impl().query_audit_log(filters, opts)
  def authenticate(username, password, opts \\ []), do: impl().authenticate(username, password, opts)
  def authenticate_with_session(username, password, opts \\ []), do: impl().authenticate_with_session(username, password, opts)
  def register_user(ca_instance_id, attrs, opts \\ []), do: impl().register_user(ca_instance_id, attrs, opts)
  def needs_setup?(ca_instance_id, opts \\ []), do: impl().needs_setup?(ca_instance_id, opts)
  def get_user_by_username(username, ca_instance_id \\ "default", opts \\ []), do: impl().get_user_by_username(username, ca_instance_id, opts)
  def reset_password(user_id, new_password, opts \\ []), do: impl().reset_password(user_id, new_password, opts)
  def update_user_profile(user_id, attrs, opts \\ []), do: impl().update_user_profile(user_id, attrs, opts)
  def verify_and_change_password(user_id, current_password, new_password, opts \\ []), do: impl().verify_and_change_password(user_id, current_password, new_password, opts)
  def list_portal_users(opts \\ []), do: impl().list_portal_users(opts)
  def create_portal_user(attrs, opts \\ []), do: impl().create_portal_user(attrs, opts)
  def suspend_user_role(role_id, opts \\ []), do: impl().suspend_user_role(role_id, opts)
  def activate_user_role(role_id, opts \\ []), do: impl().activate_user_role(role_id, opts)
  def delete_user_role(role_id, opts \\ []), do: impl().delete_user_role(role_id, opts)
  def reset_user_password(user_id, opts \\ []), do: impl().reset_user_password(user_id, opts)
  def resend_invitation(user_id, opts \\ []), do: impl().resend_invitation(user_id, opts)
  def list_hsm_devices(opts \\ []), do: impl().list_hsm_devices(opts)
  def register_hsm_device(attrs, opts \\ []), do: impl().register_hsm_device(attrs, opts)
  def probe_hsm_device(id, opts \\ []), do: impl().probe_hsm_device(id, opts)
  def deactivate_hsm_device(id, opts \\ []), do: impl().deactivate_hsm_device(id, opts)
  def list_audit_events(filters, opts \\ []), do: impl().list_audit_events(filters, opts)
  def get_ceremony(ceremony_id, opts \\ []), do: impl().get_ceremony(ceremony_id, opts)
  def generate_ceremony_keypair(algorithm, opts \\ []), do: impl().generate_ceremony_keypair(algorithm, opts)
  def distribute_ceremony_shares(ceremony_id, private_key, custodian_passwords, opts \\ []), do: impl().distribute_ceremony_shares(ceremony_id, private_key, custodian_passwords, opts)
  def complete_ceremony_root(ceremony_id, private_key, subject_dn, opts \\ []), do: impl().complete_ceremony_root(ceremony_id, private_key, subject_dn, opts)
  def complete_ceremony_sub_ca(ceremony_id, private_key, opts \\ []), do: impl().complete_ceremony_sub_ca(ceremony_id, private_key, opts)
  def cancel_ceremony(ceremony_id, opts \\ []), do: impl().cancel_ceremony(ceremony_id, opts)
  def delete_ceremony(ceremony_id, opts \\ []), do: impl().delete_ceremony(ceremony_id, opts)
  def get_issuer_key(id, opts \\ []), do: impl().get_issuer_key(id, opts)
  def list_threshold_shares(issuer_key_id, opts \\ []), do: impl().list_threshold_shares(issuer_key_id, opts)
  def reconstruct_key(issuer_key_id, custodian_passwords, opts \\ []), do: impl().reconstruct_key(issuer_key_id, custodian_passwords, opts)
  def unlock_key(issuer_key_id, custodian_passwords, opts \\ []), do: impl().unlock_key(issuer_key_id, custodian_passwords, opts)
  def is_key_active?(issuer_key_id, opts \\ []), do: impl().is_key_active?(issuer_key_id, opts)
  def sign_csr(issuer_key_id, private_key, csr_pem, cert_profile, opts \\ []), do: impl().sign_csr(issuer_key_id, private_key, csr_pem, cert_profile, opts)
  def activate_issuer_key(issuer_key_id, cert_attrs, opts \\ []), do: impl().activate_issuer_key(issuer_key_id, cert_attrs, opts)
  def suspend_issuer_key(issuer_key_id, opts \\ []), do: impl().suspend_issuer_key(issuer_key_id, opts)
  def reactivate_issuer_key(issuer_key_id, opts \\ []), do: impl().reactivate_issuer_key(issuer_key_id, opts)
  def retire_issuer_key(issuer_key_id, opts \\ []), do: impl().retire_issuer_key(issuer_key_id, opts)
  def archive_issuer_key(issuer_key_id, opts \\ []), do: impl().archive_issuer_key(issuer_key_id, opts)
  def list_certificates(issuer_key_id, opts \\ []), do: impl().list_certificates(issuer_key_id, opts)
  def list_certificates_by_ca(ca_instance_id, opts \\ []), do: impl().list_certificates_by_ca(ca_instance_id, opts)
  def get_certificate(serial_number, opts \\ []), do: impl().get_certificate(serial_number, opts)
  def revoke_certificate(serial_number, reason, opts \\ []), do: impl().revoke_certificate(serial_number, reason, opts)
  def list_active_ceremonies, do: impl().list_active_ceremonies()
  def fail_ceremony(ceremony_id, reason), do: impl().fail_ceremony(ceremony_id, reason)
  def initiate_witnessed_ceremony(ca_instance_id, params, opts \\ []), do: impl().initiate_witnessed_ceremony(ca_instance_id, params, opts)
  def accept_ceremony_share(ceremony_id, user_id, key_label, opts \\ []), do: impl().accept_ceremony_share(ceremony_id, user_id, key_label, opts)
  def attest_ceremony(ceremony_id, auditor_user_id, phase, details \\ %{}, opts \\ []), do: impl().attest_ceremony(ceremony_id, auditor_user_id, phase, details, opts)
  def check_ceremony_readiness(ceremony_id, opts \\ []), do: impl().check_ceremony_readiness(ceremony_id, opts)
  def execute_ceremony_keygen(ceremony_id, custodian_passwords, opts \\ []), do: impl().execute_ceremony_keygen(ceremony_id, custodian_passwords, opts)
  def list_ceremony_attestations(ceremony_id, opts \\ []), do: impl().list_ceremony_attestations(ceremony_id, opts)
  def get_ceremony_by_issuer_key(issuer_key_id, opts \\ []), do: impl().get_ceremony_by_issuer_key(issuer_key_id, opts)
  def list_my_ceremony_shares(user_id, opts \\ []), do: impl().list_my_ceremony_shares(user_id, opts)
  def list_my_witness_ceremonies(auditor_user_id, opts \\ []), do: impl().list_my_witness_ceremonies(auditor_user_id, opts)
end
