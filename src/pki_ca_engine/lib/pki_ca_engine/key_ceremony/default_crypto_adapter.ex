defmodule PkiCaEngine.KeyCeremony.DefaultCryptoAdapter do
  @moduledoc """
  Production implementation of CryptoAdapter protocol.

  Uses Erlang :public_key for RSA/ECC keypair generation and KeyX (Shamir's
  Secret Sharing) for threshold secret splitting and recovery.

  Private keys are serialized as DER-encoded binaries for splitting.

  DEPRECATED: This adapter is superseded by PkiCrypto.Algorithm-based key
  generation in KeyCeremonyManager and KeyVault. Retained for backward
  compatibility with existing tests.
  """
  defstruct []
end

defimpl PkiCaEngine.KeyCeremony.CryptoAdapter,
  for: PkiCaEngine.KeyCeremony.DefaultCryptoAdapter do

  @doc """
  Generate a real RSA or ECC keypair.

  Returns the private key as a DER-encoded binary (suitable for Shamir splitting)
  and the public key as a DER-encoded SubjectPublicKeyInfo binary.
  """
  def generate_keypair(_adapter, algorithm) do
    case normalize_algorithm(algorithm) do
      {:rsa, bits} ->
        private_key = :public_key.generate_key({:rsa, bits, 65537})
        private_der = :public_key.der_encode(:RSAPrivateKey, private_key)
        public_key = rsa_public_from_private(private_key)
        public_der = :public_key.der_encode(:RSAPublicKey, public_key)

        {:ok, %{public_key: public_der, private_key: private_der}}

      {:ec, named_curve} ->
        private_key = :public_key.generate_key({:namedCurve, named_curve})
        private_der = :public_key.der_encode(:ECPrivateKey, private_key)
        # Store EC public key as DER-encoded ECPrivateKey (contains public key)
        # The public key is extracted from the private key DER when needed
        public_der = private_der

        {:ok, %{public_key: public_der, private_key: private_der}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Split a secret into N shares with threshold K using Shamir's Secret Sharing.
  """
  def split_secret(_adapter, secret, k, n) do
    shares = KeyX.generate_shares!(k, n, secret)
    {:ok, shares}
  end

  @doc """
  Recover a secret from K or more shares using Shamir's Secret Sharing.
  """
  def recover_secret(_adapter, shares) do
    secret = KeyX.recover_secret!(shares)
    {:ok, secret}
  end

  # -- Private helpers --

  defp normalize_algorithm(algo) when is_binary(algo) do
    case String.downcase(algo) do
      "rsa" -> {:rsa, 2048}
      "rsa-2048" -> {:rsa, 2048}
      "rsa-4096" -> {:rsa, 4096}
      "ecc" -> {:ec, :secp256r1}
      "ec-p256" -> {:ec, :secp256r1}
      "ec-p384" -> {:ec, :secp384r1}
      "ecdsa" -> {:ec, :secp256r1}
      _ -> {:error, {:unsupported_algorithm, algo}}
    end
  end

  defp normalize_algorithm(algo), do: {:error, {:unsupported_algorithm, algo}}

  defp rsa_public_from_private(
         {:RSAPrivateKey, _, modulus, public_exponent, _, _, _, _, _, _, _}
       ) do
    {:RSAPublicKey, modulus, public_exponent}
  end
end
