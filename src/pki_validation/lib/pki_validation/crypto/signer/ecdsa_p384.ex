defmodule PkiValidation.Crypto.Signer.EcdsaP384 do
  @moduledoc """
  ECDSA with SHA-384 over secp384r1 (P-384).

  Same at-rest format as `EcdsaP256` — the private key is the raw scalar.
  """

  @behaviour PkiValidation.Crypto.Signer

  # ecdsa-with-SHA384 AlgorithmIdentifier (RFC 5754) — no params
  @algorithm_identifier_der <<0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03,
                              0x03>>

  @ecdsa_sha384_oid {1, 2, 840, 10045, 4, 3, 3}
  @algorithm_identifier_record {:AlgorithmIdentifier, @ecdsa_sha384_oid, :asn1_NOVALUE}

  @secp384r1_oid {1, 3, 132, 0, 34}

  @impl true
  def decode_private_key(raw_scalar) when is_binary(raw_scalar), do: raw_scalar

  @impl true
  def sign(tbs, raw_scalar) when is_binary(tbs) and is_binary(raw_scalar) do
    ec_priv_record =
      {:ECPrivateKey, 1, raw_scalar, {:namedCurve, @secp384r1_oid}, :asn1_NOVALUE, :asn1_NOVALUE}

    :public_key.sign(tbs, :sha384, ec_priv_record)
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: @algorithm_identifier_record
end
