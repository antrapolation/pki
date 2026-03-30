defmodule PkiAuditTrail.Actions do
  @moduledoc """
  Defined audit action constants from the PKI system design spec.
  """

  @actions [
    "ceremony_started", "ceremony_completed",
    "key_generated", "key_activated", "key_suspended",
    "csr_submitted", "csr_verified", "csr_approved", "csr_rejected",
    "certificate_issued", "certificate_revoked",
    "user_created", "user_updated", "user_deleted",
    "keystore_configured",
    "keypair_access_granted", "keypair_access_revoked",
    "login", "logout",
    "ca_instance_created", "ca_instance_status_changed",
    "ra_instance_created", "ra_instance_status_changed",
    "cert_profile_created", "cert_profile_updated",
    "hierarchy_modified",
    "issuer_key_rotation_started", "cert_profile_issuer_key_changed", "issuer_key_archived"
  ]

  def all, do: @actions
  def valid?(action) when is_binary(action), do: action in @actions
  def valid?(_), do: false
end
