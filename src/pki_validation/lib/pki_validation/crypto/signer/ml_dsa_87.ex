defmodule PkiValidation.Crypto.Signer.MlDsa87 do
  @moduledoc "ML-DSA-87 (FIPS 204) OCSP/CRL signer. See `MlDsa44` for details."
  @behaviour PkiValidation.Crypto.Signer

  @oid {2, 16, 840, 1, 101, 3, 4, 3, 19}
  @algorithm_identifier_der <<0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                              0x03, 0x13>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = PkiOqsNif.sign("ML-DSA-87", private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
