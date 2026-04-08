defmodule PkiValidation.Crypto.Signer do
  @moduledoc """
  Behaviour for OCSP/CRL signing algorithms.

  Each concrete signer module owns three things:

    * the AlgorithmIdentifier DER blob (RFC 5754 form)
    * private key decoding (raw at-rest bytes → Erlang term usable by
      `:public_key.sign/3`)
    * the sign-tbs primitive

  `SigningKeyStore` calls `decode_private_key/1` once at load time and
  caches the decoded term in process state. Signers are then called with
  the pre-decoded key, avoiding per-signature parsing and structurally
  preventing the RSA "raw DER passed to sign/3" crash class.

  To add a new signer (e.g. ML-DSA, KAZ-SIGN):

    1. Add the algorithm string to `PkiValidation.Schema.SigningKeyConfig`
       `@valid_algorithms`
    2. Create `PkiValidation.Crypto.Signer.<Name>` implementing this
       behaviour
    3. Add one line to `PkiValidation.Crypto.Signer.Registry.@mapping`
  """

  @doc """
  Decode the at-rest private key bytes into the form `:public_key.sign/3`
  (or the equivalent NIF entry point) expects.

  Called once per key at `SigningKeyStore` load time. The returned term is
  cached and passed back to `sign/2` on every signature.
  """
  @callback decode_private_key(binary()) :: term()

  @doc """
  Sign the TBS DER bytes, returning the raw signature bytes (no BIT STRING
  wrapping — the ASN.1 encoder handles that).
  """
  @callback sign(tbs :: binary(), private_key :: term()) :: binary()

  @doc """
  Return the DER-encoded AlgorithmIdentifier for this signer.

  This is the complete pre-encoded byte sequence for an RFC 5754
  AlgorithmIdentifier with the algorithm OID and (for RSA) the NULL params,
  ready to splice into the `OCSP.asn1` ANY-typed field. The OCSP path uses
  this form because the local `OCSP.asn1` schema declares
  `AlgorithmIdentifier` as `ANY` and the codec passes the bytes through
  unchanged.

  Static per module — each signer owns its own blob.
  """
  @callback algorithm_identifier_der() :: binary()

  @doc """
  Return the AlgorithmIdentifier as an Erlang record.

  Shape: `{:AlgorithmIdentifier, oid_tuple, params}` where `params` is
  either `:asn1_NOVALUE` (ECDSA) or `<<5, 0>>` (RSA NULL params).

  The CRL path uses this form because `:public_key.der_encode(:TBSCertList,
  ...)` requires the typed Erlang record (it cannot accept a pre-encoded DER
  blob in that field). `:public_key` does NOT expose `AlgorithmIdentifier`
  as a top-level encode/decode type, so the DER blob form is not
  interchangeable with the record form via a generic codec — both shapes
  must be authored explicitly per signer.
  """
  @callback algorithm_identifier_record() :: tuple()
end
