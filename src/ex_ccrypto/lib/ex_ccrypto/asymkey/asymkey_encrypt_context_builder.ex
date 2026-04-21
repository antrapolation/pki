# Public API
defmodule ExCcrypto.Asymkey.AsymkeyEncryptContextBuilder do
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Asymkey.RSA.RSAEncryptContext
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.Ecc.EciesEncryptContext

  def encrypt_context(algo \\ :ecc)

  def encrypt_context(:ecc) do
    %EciesEncryptContext{}
  end

  def encrypt_context(:rsa) do
    %RSAEncryptContext{}
  end

  # def encrypt_context(:ml_kem) do
  #  %MlKemContext{}
  # end

  # def encrypt_context(:kaz_kem) do
  #  %KazKemContext{}
  # end

  def encrypt_context(%EccPublicKey{} = pubkey) do
    %EciesEncryptContext{} |> ContextConfig.set(:add_encryption_key, pubkey)
  end

  def encrypt_context(%RSAPublicKey{} = pubkey) do
    %RSAEncryptContext{} |> ContextConfig.set(:add_encryption_key, pubkey)
  end

  # def encrypt_context(%MlKemPublicKey{} = pubkey) do
  #  %MlKemContext{} |> ContextConfig.set(:add_encryption_key, pubkey)
  # end

  # def encrypt_context(%KazKemPublicKey{} = pubkey) do
  #  %KazKemContext{} |> ContextConfig.set(:add_encryption_key, pubkey)
  # end

  def encrypt_context(X509.Certificate = cert) do
    pubkey = X509Certificate.public_key(cert)

    case pubkey do
      {:RSAPublicKey, _, _} -> encrypt_context(RSAPublicKey.encap(pubkey))
      _ -> encrypt_context(EccPublicKey.from_certificate(cert))
    end
  end

  def encrypt_context(algo), do: {:error, {:unsupported_encrypt_context, algo}}

  def encryption_context_from_public_key(%EccPublicKey{} = pubkey),
    do: %EciesEncryptContext{} |> ContextConfig.set(:add_encryption_key, pubkey)

  def encryption_context_from_public_key(%RSAPublicKey{} = pubkey),
    do: %RSAEncryptContext{} |> ContextConfig.set(:add_encryption_key, pubkey)

  def encryption_context_from_public_key(pubkey),
    do: {:error, {:unknown_public_key_context_for_encryption, pubkey}}
end
