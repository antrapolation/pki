defmodule PkiValidation.Crypto.Signer.Rsa4096 do
  @moduledoc """
  RSA-4096 with SHA-256.

  Same shape as `Rsa2048` — the only difference is the key size. Both use
  sha256WithRSAEncryption as the signature algorithm. `decode_private_key/1`
  runs once at `SigningKeyStore` load time.
  """

  @behaviour PkiValidation.Crypto.Signer

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
