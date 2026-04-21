# Public Struct
defmodule ExCcrypto.Asymkey.Ecc.EccVerifyContext do
  alias ExCcrypto.Asymkey.Ecc.EccVerifyContext
  use TypedStruct

  typedstruct do
    field(:digest_algo, atom(), default: :sha512)
    field(:verification_key, any())
    field(:digest_context, any())
    field(:data, any())
  end

  def set_digest_algo(ctx, algo), do: %{ctx | digest_algo: algo}
  def set_verification_key(ctx, key), do: %{ctx | verification_key: key}
  def reset_digest_context(%EccVerifyContext{} = ctx), do: %{ctx | digest_context: nil}
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Asymkey.Ecc.EccVerifyContext do
  alias ExCcrypto.Asymkey.Ecc.EccVerifyContext

  def set(ctx, :verification_key, value, _opts),
    do: EccVerifyContext.set_verification_key(ctx, value)

  def set(ctx, :digest_algo, value, _opts),
    do: EccVerifyContext.set_digest_algo(ctx, value)

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key) do
    %{}
  end

  def info(_ctx, :setter_key),
    do: %{
      verification_key: "Set the verification public key in respective public key format"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on EccVerifyContext. No info key '#{info}' found"}
end

alias ExCcrypto.Asymkey.AsymkeyVerify

defimpl AsymkeyVerify, for: ExCcrypto.Asymkey.Ecc.EccVerifyContext do
  require X509.ASN1
  alias ExCcrypto.Asymkey.AsymkeyHelper
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.Ecc.EccVerifyContext

  def verify_init(%EccVerifyContext{verification_key: X509.ASN1.otp_certificate()} = ctx, opts) do
    verify_init(
      %{ctx | verification_key: EccPublicKey.from_certificate(ctx.verification_key)},
      opts
    )
  end

  def verify_init(%EccVerifyContext{verification_key: %EccPublicKey{}} = ctx, _opts) do
    dgst = :crypto.hash_init(ctx.digest_algo)
    %{ctx | digest_context: dgst}
  end

  def verify_update(ctx, data) do
    %{ctx | digest_context: :crypto.hash_update(ctx.digest_context, data)}
  end

  def verify_final(ctx, signature) do
    dgstRes = :crypto.hash_final(ctx.digest_context)

    verRes =
      :public_key.verify(
        dgstRes,
        ctx.digest_algo,
        signature,
        KeyEncoding.to_native!(ctx.verification_key)
      )

    {:ok, %{verification_result: verRes, context: EccVerifyContext.reset_digest_context(ctx)}}
  end

  defdelegate verify(ctx, data, signature, opts), to: AsymkeyHelper

  # def verify(ctx, data, signature, opts) do
  #  AsymkeyVerify.verify_init(ctx, opts)
  #  |> AsymkeyVerify.verify_update(data)
  #  |> AsymkeyVerify.verify_final(signature)
  # end
end
