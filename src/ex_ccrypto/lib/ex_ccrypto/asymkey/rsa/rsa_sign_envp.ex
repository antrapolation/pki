# Public Struct
defmodule ExCcrypto.Asymkey.RSA.RSASignEnvp do
  alias ExCcrypto.Asymkey.RSA.RSASignEnvp
  use TypedStruct

  typedstruct do
    field(:signature, any())
    field(:sign_context, any())
    field(:info, map(), default: %{})
  end

  def set_signature(ctx, sign), do: %RSASignEnvp{ctx | signature: sign}

  def get_signature(ctx), do: ctx.signature

  def set_sign_context(ctx, sctx), do: %RSASignEnvp{ctx | sign_context: sctx}

  def get_sign_context(ctx), do: ctx.sign_context

  def set_info(ctx, key, val) do
    case Map.has_key?(ctx.info, key) do
      true ->
        %RSASignEnvp{ctx | info: Map.put(ctx.info, key, val)}

      false ->
        %RSASignEnvp{ctx | info: Map.put_new(ctx.info, key, val)}
    end
  end

  def get_info(%RSASignEnvp{} = ctx, key), do: ctx.info[key]
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Asymkey.RSA.RSASignEnvp do
  alias ExCcrypto.Asymkey.RSA.RSASignEnvp
  alias ExCcrypto.ContextConfig

  def get(ctx, :signature, _default, _opts), do: RSASignEnvp.get_signature(ctx)
  def get(ctx, :sign_context, _default, _opts), do: RSASignEnvp.get_sign_context(ctx)

  def get(ctx, key, default, opts) do
    ContextConfig.get(RSASignEnvp.get_sign_context(ctx), key, default, opts)
  end

  def set(_ctx, key, _value, _opts), do: {:error, {:unknown_setter_key, key}}

  def info(_ctx, :getter_key) do
    %{
      signature: "Return the signature output in binary",
      sign_context: "Return the signing context that produced the signature"
    }
  end

  def info(_ctx, :setter_key),
    do: %{}

  def info(_ctx, info),
    do: %{error: "Info operation error on RSASignEnvp. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey.AsymkeyVerify, for: ExCcrypto.Asymkey.RSA.RSASignEnvp do
  require X509.ASN1
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Asymkey.RSA.RSASignContext
  alias ExCcrypto.Asymkey.RSA.RSASignEnvp
  alias ExCcrypto.Asymkey.AsymkeyHelper
  alias ExCcrypto.Asymkey.KeyEncoding

  def verify_init(
        %RSASignEnvp{} = ctx,
        %{verification_key: X509.ASN1.otp_certificate() = key}
      ) do
    verify_init(
      ctx,
      %{verification_key: RSAPublicKey.from_certificate(key)}
    )
  end

  def verify_init(
        %RSASignEnvp{sign_context: %RSASignContext{pre_sign_digest_algo: pre_sign_dgst_algo}} =
          ctx,
        %{verification_key: %RSAPublicKey{} = key}
      )
      when not is_nil(pre_sign_dgst_algo) do
    vctx = RSASignEnvp.set_info(ctx, :verification_key, key)
    dgst = :crypto.hash_init(ctx.sign_context.pre_sign_digest_algo)
    RSASignEnvp.set_info(vctx, :digest_context, dgst)
  end

  def verify_init(
        %RSASignEnvp{} = ctx,
        %{verification_key: %RSAPublicKey{} = key}
      ) do
    RSASignEnvp.set_info(ctx, :verification_key, key)
    |> RSASignEnvp.set_info(:data, [])
  end

  def verify_update(%RSASignEnvp{info: %{digest_context: dgst_ctx}} = ctx, data)
      when not is_nil(dgst_ctx) do
    RSASignEnvp.set_info(
      ctx,
      :digest_context,
      :crypto.hash_update(RSASignEnvp.get_info(ctx, :digest_context), data)
    )
  end

  def verify_update(%RSASignEnvp{} = ctx, data) do
    RSASignEnvp.set_info(
      ctx,
      :data,
      RSASignEnvp.get_info(ctx, :data) ++ data
    )
  end

  def verify_final(%RSASignEnvp{info: %{digest_context: dgst_ctx}} = ctx, signature)
      when not is_nil(dgst_ctx) do
    # dgstRes = :crypto.hash_final(RSASignEnvp.get_info(ctx, :digest_context))
    dgstRes = :crypto.hash_final(dgst_ctx)

    verRes =
      :public_key.verify(
        dgstRes,
        ctx.sign_context.digest_algo,
        signature,
        KeyEncoding.to_native!(RSASignEnvp.get_info(ctx, :verification_key))
      )

    {:ok, %{verification_result: verRes, context: ctx}}
  end

  def verify_final(%RSASignEnvp{} = ctx, signature) do
    verRes =
      :public_key.verify(
        RSASignEnvp.get_info(ctx, :data),
        ctx.sign_context.digest_algo,
        signature,
        KeyEncoding.to_native!(RSASignEnvp.get_info(ctx, :verification_key))
      )

    {:ok, %{verification_result: verRes, context: ctx}}
  end

  defdelegate verify(ctx, data, signature, opts), to: AsymkeyHelper
end
