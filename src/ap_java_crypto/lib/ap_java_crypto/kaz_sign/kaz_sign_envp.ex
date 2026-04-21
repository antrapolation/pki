defmodule ApJavaCrypto.KazSign.KazSignEnvp do
  alias ApJavaCrypto.KazSign.KazSignContext
  alias ApJavaCrypto.KazSign.KazSignEnvp

  use TypedStruct

  typedstruct do
    field(:signature, any())
    field(:sign_context, any())
    field(:info, map(), default: %{})
  end

  def set_signature(ctx, sign), do: %KazSignEnvp{ctx | signature: sign}

  def get_signature(ctx), do: ctx.signature

  def set_sign_context(ctx, sctx), do: %KazSignEnvp{ctx | sign_context: sctx}

  def get_sign_context(ctx), do: ctx.sign_context

  def set_info(ctx, key, val) do
    case Map.has_key?(ctx.info, key) do
      true ->
        %KazSignEnvp{ctx | info: Map.put(ctx.info, key, val)}

      false ->
        %KazSignEnvp{ctx | info: Map.put_new(ctx.info, key, val)}
    end
  end

  def get_info(%KazSignEnvp{} = ctx, key), do: ctx.info[key]

  def sanitize(%KazSignEnvp{} = ctx) do
    %KazSignEnvp{ctx | sign_context: %KazSignContext{ctx.sign_context | private_key: nil}}
  end
end

alias ApJavaCrypto.KazSign.KazSignEnvp

defimpl ExCcrypto.ContextConfig, for: KazSignEnvp do
  alias ApJavaCrypto.KazSign.KazSignEnvp
  alias ExCcrypto.ContextConfig

  def get(ctx, :signature, _default, _opts), do: KazSignEnvp.get_signature(ctx)
  def get(ctx, :sign_context, _default, _opts), do: KazSignEnvp.get_sign_context(ctx)

  def get(ctx, key, default, opts) do
    ContextConfig.get(KazSignEnvp.get_sign_context(ctx), key, default, opts)
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
    do: %{error: "Info operation error on KazSignEnvp. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey.AsymkeyVerify, for: KazSignEnvp do
  require X509.ASN1
  alias ApJavaCrypto.KazSign.KazSignPublicKey
  alias ApJavaCrypto.KazSign.KazSignContext
  alias ApJavaCrypto.KazSign.KazSignEnvp
  alias ExCcrypto.Asymkey.AsymkeyHelper

  def verify_init(
        %KazSignEnvp{sign_context: %KazSignContext{digest_algo: sign_dgst_algo}} =
          ctx,
        %{verification_key: %KazSignPublicKey{} = key}
      )
      when not is_nil(sign_dgst_algo) do
    vctx = KazSignEnvp.set_info(ctx, :verification_key, key)
    dgst = :crypto.hash_init(ctx.sign_context.digest_algo)
    KazSignEnvp.set_info(vctx, :digest_context, dgst)
  end

  def verify_init(
        %KazSignEnvp{sign_context: %KazSignContext{digest_algo: sign_dgst_algo}} =
          ctx,
        %{verification_key: {:der, {:ap_java_crypto, _cert}} = key}
      )
      when not is_nil(sign_dgst_algo) do
    vctx = KazSignEnvp.set_info(ctx, :verification_key, key)
    dgst = :crypto.hash_init(ctx.sign_context.digest_algo)
    KazSignEnvp.set_info(vctx, :digest_context, dgst)
  end

  # def verify_init(
  #      %KazSignEnvp{} = ctx,
  #      %{verification_key: X509.ASN1.otp_certificate() = key}
  #    ) do
  #  verify_init(
  #    ctx,
  #    %{verification_key: EccPublicKey.from_certificate(key)}
  #  )
  # end

  # def verify_init(
  #      %KazSignEnvp{} = ctx,
  #      %{verification_key: %KazSignPublicKey{} = key}
  #    ) do
  #  KazSignEnvp.set_info(ctx, :verification_key, key)
  #  |> KazSignEnvp.set_info(:data, [])
  # end

  def verify_update(%KazSignEnvp{info: %{digest_context: dgst_ctx}} = ctx, data)
      when not is_nil(dgst_ctx) do
    KazSignEnvp.set_info(
      ctx,
      :digest_context,
      :crypto.hash_update(KazSignEnvp.get_info(ctx, :digest_context), data)
    )
  end

  # def verify_update(%KazSignEnvp{} = ctx, data) do
  #  KazSignEnvp.set_info(
  #    ctx,
  #    :data,
  #    KazSignEnvp.get_info(ctx, :data) ++ data
  #  )
  # end

  def verify_final(%KazSignEnvp{info: %{digest_context: dgst_ctx}} = ctx, signature)
      when not is_nil(dgst_ctx) do
    # dgstRes = :crypto.hash_final(EccSignEnvp.get_info(ctx, :digest_context))
    dgstRes = :crypto.hash_final(dgst_ctx)

    pubkey = KazSignEnvp.get_info(ctx, :verification_key)

    case pubkey do
      %KazSignPublicKey{} ->
        with {:ok, true} <-
               ApJavaCrypto.verify(
                 dgstRes,
                 signature,
                 {pubkey.variant, :public_key, pubkey.value}
               ) do
          {:ok, %{verification_result: true, context: ctx}}
        else
          _err -> {:ok, %{verification_result: false, context: ctx}}
        end

      {:der, {:ap_java_crypto, cert}} ->
        with {:ok, true} <-
               ApJavaCrypto.verify(
                 dgstRes,
                 signature,
                 {:cert, cert}
               ) do
          {:ok, %{verification_result: true, context: ctx}}
        else
          _err -> {:ok, %{verification_result: false, context: ctx}}
        end
    end
  end

  # def verify_final(%KazSignEnvp{} = ctx, signature) do
  #  verRes =
  #    ApJavaCrypto.verify(dgstRes, signature, KazSignEnvp.get_info(ctx, :verification_key))

  #  # :public_key.verify(
  #  #  EccSignEnvp.get_info(ctx, :data),
  #  #  ctx.sign_context.digest_algo,
  #  #  signature,
  #  #  KeyEncoding.to_native!(EccSignEnvp.get_info(ctx, :verification_key))
  #  # )

  #  {:ok, %{verification_result: verRes, context: ctx}}
  # end

  defdelegate verify(ctx, data, signature, opts), to: AsymkeyHelper
end
