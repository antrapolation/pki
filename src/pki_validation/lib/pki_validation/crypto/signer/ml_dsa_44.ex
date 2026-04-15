defmodule PkiValidation.Crypto.Signer.MlDsa44 do
  @moduledoc """
  ML-DSA-44 (FIPS 204) OCSP/CRL signer. Private key bytes are raw NIF output —
  no encoding at rest. `decode_private_key/1` is a pass-through.
  """
  @behaviour PkiValidation.Crypto.Signer

  @oid {2, 16, 840, 1, 101, 3, 4, 3, 17}
  # Precomputed DER: SEQUENCE(OID 2.16.840.1.101.3.4.3.17).
  # Equivalent to: <<0x30, byte_size(der)>> <> :public_key.der_encode(:OBJECT_IDENTIFIER, @oid)
  @algorithm_identifier_der <<0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                              0x03, 0x11>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = PkiOqsNif.sign("ML-DSA-44", private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
