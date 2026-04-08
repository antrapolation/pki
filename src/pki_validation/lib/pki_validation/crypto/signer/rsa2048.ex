defmodule PkiValidation.Crypto.Signer.Rsa2048 do
  @moduledoc """
  RSA-2048 with SHA-256.

  The at-rest private key is the DER encoding of an `:RSAPrivateKey`
  record — this is what the existing `SigningKeyStore` stores (the
  decrypted bytes from AES-256-GCM).

  `decode_private_key/1` decodes this once at load time into the
  `:RSAPrivateKey` Erlang record. `sign/2` receives that decoded record
  and passes it directly to `:public_key.sign/3`. This structurally
  prevents the D1 class of bug where raw DER bytes were being passed to
  `:public_key.sign/3` (which requires a decoded record) at sign time.
  """

  @behaviour PkiValidation.Crypto.Signer

  # sha256WithRSAEncryption AlgorithmIdentifier (RFC 4055)
  # NULL params for RSA signatures
  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                              0x01, 0x0B, 0x05, 0x00>>

  @rsa_sha256_oid {1, 2, 840, 113_549, 1, 1, 11}
  @algorithm_identifier_record {:AlgorithmIdentifier, @rsa_sha256_oid, <<5, 0>>}

  @impl true
  def decode_private_key(der) when is_binary(der) do
    :public_key.der_decode(:RSAPrivateKey, der)
  end

  @impl true
  def sign(tbs, rsa_priv_record) when is_binary(tbs) and is_tuple(rsa_priv_record) do
    :public_key.sign(tbs, :sha256, rsa_priv_record)
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: @algorithm_identifier_record
end
