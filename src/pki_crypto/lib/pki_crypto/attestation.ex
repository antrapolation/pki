defmodule PkiCrypto.Attestation do
  @moduledoc "Public key signing/attestation by an authority."

  alias PkiCrypto.{Algorithm, Registry}

  @doc "Sign a target's public key with the admin's signing key (attestation)."
  def attest(admin_signing_key, admin_algorithm, target_public_key) do
    algo = Registry.get(admin_algorithm)
    data = "ATTEST:" <> target_public_key
    Algorithm.sign(algo, admin_signing_key, data)
  end

  @doc "Verify that a public key was attested by a specific admin."
  def verify_attestation(admin_public_key, admin_algorithm, attestation_signature, target_public_key) do
    algo = Registry.get(admin_algorithm)
    data = "ATTEST:" <> target_public_key
    Algorithm.verify(algo, admin_public_key, attestation_signature, data)
  end
end
