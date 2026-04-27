defmodule PkiAuditTrail.Actions do
  @moduledoc """
  Defined audit action constants from the PKI system design spec.
  """

  @actions [
    # Certificate lifecycle
    "certificate_issued", "certificate_revoked",
    # CSR
    "csr_submitted", "csr_verified", "csr_approved", "csr_rejected",
    "csr_submitted_via_portal", "csr_signed",
    # DCV
    "dcv_started", "dcv_passed",
    # Ceremony
    "ceremony_started", "ceremony_completed", "ceremony_initiated",
    "ceremony_cancelled", "ceremony_deleted",
    "ceremony_share_accepted", "ceremony_key_generated",
    "custodian_share_accepted",
    # Auditor witness
    "auditor_witnessed", "auditor_accepted_ceremony", "auditor_signed_transcript",
    # Key / Issuer key lifecycle
    "key_generated", "key_activated", "key_suspended",
    "key_activated_with_external_cert",
    "issuer_key_unlocked", "issuer_key_suspended", "issuer_key_reactivated",
    "issuer_key_retired", "issuer_key_archived",
    "issuer_key_rotation_started", "cert_profile_issuer_key_changed",
    # Activation lease
    "activation_lease_granted", "activation_custodian_authenticated",
    # Keystore / Keypair
    "keystore_configured",
    "keypair_access_granted", "keypair_access_revoked",
    # HSM
    "hsm_device_probed", "hsm_wizard_completed",
    # User / Profile
    "user_created", "user_updated", "user_deleted",
    "login", "logout",
    "password_changed", "profile_updated",
    # API keys
    "api_key_created", "api_key_revoked",
    # CA / RA instance
    "ca_instance_created", "ca_instance_renamed", "ca_instance_status_changed",
    "ra_instance_created", "ra_instance_status_changed",
    # Cert profiles
    "cert_profile_created", "cert_profile_updated",
    # Hierarchy
    "hierarchy_modified"
  ]

  def all, do: @actions
  def valid?(action) when is_binary(action), do: action in @actions
  def valid?(_), do: false
end
