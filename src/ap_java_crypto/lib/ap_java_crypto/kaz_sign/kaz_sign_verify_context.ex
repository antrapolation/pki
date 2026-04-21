defmodule ApJavaCrypto.KazSign.KazSignVerifyContext do
  alias ApJavaCrypto.KazSign.KazSignVerifyContext

  use TypedStruct

  typedstruct do
    field(:digest_algo, atom(), default: :sha512)
    field(:verification_key, any())
    field(:digest_context, any())
    field(:data, any())
  end

  def set_digest_algo(ctx, algo), do: %{ctx | digest_algo: algo}
  def set_verification_key(ctx, key), do: %{ctx | verification_key: key}
  def reset_digest_context(%KazSignVerifyContext{} = ctx), do: %{ctx | digest_context: nil}
end

alias ApJavaCrypto.KazSign.KazSignVerifyContext

defimpl ExCcrypto.ContextConfig, for: KazSignVerifyContext do
  def set(ctx, :verification_key, value, _opts),
    do: KazSignVerifyContext.set_verification_key(ctx, value)

  def set(ctx, :digest_algo, value, _opts),
    do: KazSignVerifyContext.set_digest_algo(ctx, value)

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
    do: %{error: "Info operation error on KazSignVerifyContext. No info key '#{info}' found"}
end

# alias ExCcrypto.Asymkey.AsymkeyVerify
#
# defimpl AsymkeyVerify, for: KazSignVerifyContext do
#  require X509.ASN1
#  alias ExCcrypto.Asymkey.KazSign.KazSignVerifyContext
#  alias ExCcrypto.Asymkey.KazSign.KazSignPublicKey
#  alias ExCcrypto.Asymkey.AsymkeyHelper
#
#  # 
#  # certificate as verification key
#  #
#  def verify_init(
#        %KazSignVerifyContext{verification_key: {:der, {:ap_java_crypto, _cert}}} = ctx,
#        opts
#      ) do
#    verify_init(
#      %{ctx | verification_key: ctx.verification_key},
#      opts
#    )
#  end
#
#  # 
#  # public key as verification key
#  #
#  def verify_init(%KazSignVerifyContext{verification_key: %KazSignPublicKey{}} = ctx, _opts) do
#    dgst = :crypto.hash_init(ctx.digest_algo)
#    %{ctx | digest_context: dgst}
#  end
#
#  def verify_update(ctx, data) do
#    %{ctx | digest_context: :crypto.hash_update(ctx.digest_context, data)}
#  end
#
#  def verify_final(ctx, signature) do
#    dgstRes = :crypto.hash_final(ctx.digest_context)
#
#    verRes =
#      ApJavaCrypto.verify(dgstRes, signature, ctx.verification_key)
#
#    {:ok, %{verification_result: verRes, context: KazSignVerifyContext.reset_digest_context(ctx)}}
#  end
#
#  defdelegate verify(ctx, data, signature, opts), to: AsymkeyHelper
# end
