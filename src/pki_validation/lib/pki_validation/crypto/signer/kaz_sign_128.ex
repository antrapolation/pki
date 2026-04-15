defmodule PkiValidation.Crypto.Signer.KazSign128 do
  @moduledoc """
  KAZ-SIGN-128 (Malaysia PQC) OCSP/CRL signer.

  OID is a PLACEHOLDER (`1.3.6.1.4.1.99999.1.1.1`) pending Antrapolation's
  IANA PEN assignment. Replace via `PkiCrypto.AlgorithmRegistry` override
  once the real OID lands — the DER blob in this module is a static default
  used when no override is configured.
  """
  @behaviour PkiValidation.Crypto.Signer

  @oid {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}
  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D,
                              0x1F, 0x01, 0x01, 0x01>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = KazSign.sign_detached(128, tbs, private_key)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
