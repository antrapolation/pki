defmodule PkiCaEngine.CredentialManager.Attestation do
  @moduledoc """
  Public key signing/attestation by an authority.
  Delegates to PkiCrypto.Attestation for the actual crypto operations.
  """

  defdelegate attest(admin_signing_key, admin_algorithm, target_public_key), to: PkiCrypto.Attestation
  defdelegate verify_attestation(admin_public_key, admin_algorithm, attestation_signature, target_public_key), to: PkiCrypto.Attestation
end
