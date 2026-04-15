defmodule PkiValidation.Crypto.Signer.KazSign192 do
  @moduledoc "KAZ-SIGN-192 OCSP/CRL signer. See `KazSign128` for placeholder OID details."
  @behaviour PkiValidation.Crypto.Signer

  @oid {1, 3, 6, 1, 4, 1, 62395, 2, 2, 2}
  # SEQUENCE(OID 1.3.6.1.4.1.62395.2.2.2) — KAZ-SIGN-192 reference impl OID
  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xE7,
                              0x3B, 0x02, 0x02, 0x02>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = KazSign.sign_detached(192, tbs, private_key)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
