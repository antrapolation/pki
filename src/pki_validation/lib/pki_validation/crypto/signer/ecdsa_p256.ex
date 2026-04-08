defmodule PkiValidation.Crypto.Signer.EcdsaP256 do
  @moduledoc """
  ECDSA with SHA-256 over secp256r1 (P-256).

  The at-rest private key for ECC is the raw private scalar bytes as
  produced by `:crypto.generate_key(:ecdh, :secp256r1)`. `decode_private_key/1`
  is a passthrough — no parsing is required.

  At sign time the scalar is wrapped in an `ECPrivateKey` record that
  `:public_key.sign/3` accepts.
  """

  @behaviour PkiValidation.Crypto.Signer

  # ecdsa-with-SHA256 AlgorithmIdentifier (RFC 5754) — no params
  # SEQUENCE { OID 1.2.840.10045.4.3.2 }
  @algorithm_identifier_der <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03,
                              0x02>>

  @ecdsa_sha256_oid {1, 2, 840, 10045, 4, 3, 2}
  @algorithm_identifier_record {:AlgorithmIdentifier, @ecdsa_sha256_oid, :asn1_NOVALUE}

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  @impl true
  def decode_private_key(raw_scalar) when is_binary(raw_scalar), do: raw_scalar

  @impl true
  def sign(tbs, raw_scalar) when is_binary(tbs) and is_binary(raw_scalar) do
    ec_priv_record =
      {:ECPrivateKey, 1, raw_scalar, {:namedCurve, @secp256r1_oid}, :asn1_NOVALUE, :asn1_NOVALUE}

    :public_key.sign(tbs, :sha256, ec_priv_record)
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: @algorithm_identifier_record
end
