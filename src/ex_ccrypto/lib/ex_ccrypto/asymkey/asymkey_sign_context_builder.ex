# Public API
defmodule ExCcrypto.Asymkey.AsymkeySignContextBuilder do
  alias ExCcrypto.Asymkey.RSA.RSAVerifyContext
  alias ExCcrypto.Asymkey.RSA.RSAPrivateKey
  alias ExCcrypto.Asymkey.RSA.RSASignContext
  alias ExCcrypto.Asymkey.Ecc.EccVerifyContext
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeySignContextBuilder
  alias ExCcrypto.Asymkey.Ecc.EccPrivateKey
  alias ExCcrypto.Asymkey.Ecc.EccSignContext
  def sign_context(algo \\ :ecc)

  def sign_context(:ecc), do: %EccSignContext{}
  def sign_context(:rsa), do: %RSASignContext{}

  # 
  # Sign Context based on Private Key
  #
  def sign_context(%EccPrivateKey{} = privkey) do
    AsymkeySignContextBuilder.sign_context(:ecc)
    |> ContextConfig.set(:private_key, privkey)
  end

  def sign_context(%RSAPrivateKey{} = privkey) do
    AsymkeySignContextBuilder.sign_context(:rsa)
    |> ContextConfig.set(:private_key, privkey)
  end

  # 
  # Sign Context based on context
  #
  def sign_context(%EccSignContext{} = ctx) do
    %EccVerifyContext{}
    |> EccVerifyContext.set_digest_algo(ctx.digest_algo)
  end

  def sign_context(%RSASignContext{} = ctx) do
    %RSAVerifyContext{}
    |> RSAVerifyContext.set_digest_algo(ctx.digest_algo)
  end

  def sign(algo), do: {:error, {:unsupported_signt_context, algo}}
end
