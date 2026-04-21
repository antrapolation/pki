# Public Struct
defmodule ExCcrypto.Asymkey.Ecc.EccSignEnvp do
  alias ExCcrypto.Asymkey.Ecc.EccSignEnvp
  use TypedStruct

  typedstruct do
    field(:signature, any())
    field(:sign_context, any())
    field(:info, map(), default: %{})
  end

  def set_signature(ctx, sign), do: %EccSignEnvp{ctx | signature: sign}

  def get_signature(ctx), do: ctx.signature

  def set_sign_context(ctx, sctx), do: %EccSignEnvp{ctx | sign_context: sctx}

  def get_sign_context(ctx), do: ctx.sign_context

  def set_info(ctx, key, val) do
    case Map.has_key?(ctx.info, key) do
      true ->
        %EccSignEnvp{ctx | info: Map.put(ctx.info, key, val)}

      false ->
        %EccSignEnvp{ctx | info: Map.put_new(ctx.info, key, val)}
    end
  end

  def get_info(%EccSignEnvp{} = ctx, key), do: ctx.info[key]
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Asymkey.Ecc.EccSignEnvp do
  alias ExCcrypto.Asymkey.Ecc.EccSignEnvp
  alias ExCcrypto.ContextConfig

  def get(ctx, :signature, _default, _opts), do: EccSignEnvp.get_signature(ctx)
  def get(ctx, :sign_context, _default, _opts), do: EccSignEnvp.get_sign_context(ctx)

  def get(ctx, key, default, opts) do
    ContextConfig.get(EccSignEnvp.get_sign_context(ctx), key, default, opts)
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
    do: %{error: "Info operation error on EccSignEnvp. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey.AsymkeyVerify, for: ExCcrypto.Asymkey.Ecc.EccSignEnvp do
  require X509.ASN1
  alias ExCcrypto.Asymkey.Ecc.EccSignContext
  alias ExCcrypto.Asymkey.AsymkeyHelper
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  alias ExCcrypto.Asymkey.Ecc.EccSignEnvp

  def verify_init(
        %EccSignEnvp{} = ctx,
        %{verification_key: X509.ASN1.otp_certificate() = key}
      ) do
    verify_init(
      ctx,
      %{verification_key: EccPublicKey.from_certificate(key)}
    )
  end

  def verify_init(
        %EccSignEnvp{sign_context: %EccSignContext{pre_sign_digest_algo: pre_sign_dgst_algo}} =
          ctx,
        %{verification_key: %EccPublicKey{} = key}
      )
      when not is_nil(pre_sign_dgst_algo) do
    vctx = EccSignEnvp.set_info(ctx, :verification_key, key)
    dgst = :crypto.hash_init(ctx.sign_context.pre_sign_digest_algo)
    EccSignEnvp.set_info(vctx, :digest_context, dgst)
  end

  def verify_init(
        %EccSignEnvp{} = ctx,
        %{verification_key: %EccPublicKey{} = key}
      ) do
    EccSignEnvp.set_info(ctx, :verification_key, key)
    |> EccSignEnvp.set_info(:data, [])
  end

  def verify_update(%EccSignEnvp{info: %{digest_context: dgst_ctx}} = ctx, data)
      when not is_nil(dgst_ctx) do
    EccSignEnvp.set_info(
      ctx,
      :digest_context,
      :crypto.hash_update(EccSignEnvp.get_info(ctx, :digest_context), data)
    )
  end

  def verify_update(%EccSignEnvp{} = ctx, data) do
    EccSignEnvp.set_info(
      ctx,
      :data,
      EccSignEnvp.get_info(ctx, :data) ++ data
    )
  end

  def verify_final(%EccSignEnvp{info: %{digest_context: dgst_ctx}} = ctx, signature)
      when not is_nil(dgst_ctx) do
    # dgstRes = :crypto.hash_final(EccSignEnvp.get_info(ctx, :digest_context))
    dgstRes = :crypto.hash_final(dgst_ctx)

    verRes =
      :public_key.verify(
        dgstRes,
        ctx.sign_context.digest_algo,
        signature,
        KeyEncoding.to_native!(EccSignEnvp.get_info(ctx, :verification_key))
      )

    {:ok, %{verification_result: verRes, context: ctx}}
  end

  def verify_final(%EccSignEnvp{} = ctx, signature) do
    verRes =
      :public_key.verify(
        EccSignEnvp.get_info(ctx, :data),
        ctx.sign_context.digest_algo,
        signature,
        KeyEncoding.to_native!(EccSignEnvp.get_info(ctx, :verification_key))
      )

    {:ok, %{verification_result: verRes, context: ctx}}
  end

  defdelegate verify(ctx, data, signature, opts), to: AsymkeyHelper
end
