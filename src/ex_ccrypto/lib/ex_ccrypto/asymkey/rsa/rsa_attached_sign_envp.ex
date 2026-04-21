# Public Struct
defmodule ExCcrypto.Asymkey.RSA.RSAAttachedSignEnvp do
  alias ExCcrypto.Asymkey.RSA.RSASignEnvp
  alias ExCcrypto.Asymkey.RSA.RSAAttachedSignEnvp
  use TypedStruct

  typedstruct do
    field(:data, any())
    field(:sign_envp, RSASignEnvp.t())
    field(:info, map(), default: %{})
    # field(:verified_data, any(), default: [])
  end

  def set_data(%RSAAttachedSignEnvp{} = ctx, val), do: %RSAAttachedSignEnvp{ctx | data: val}

  def get_data(%RSAAttachedSignEnvp{} = ctx), do: ctx.data

  def set_sign_envp(%RSAAttachedSignEnvp{} = ctx, %RSASignEnvp{} = val),
    do: %RSAAttachedSignEnvp{ctx | sign_envp: val}

  def get_sign_envp(%RSAAttachedSignEnvp{} = ctx), do: ctx.sign_envp

  def set_info(ctx, key, val) do
    case Map.has_key?(ctx.info, key) do
      true ->
        %RSAAttachedSignEnvp{ctx | info: Map.put(ctx.info, key, val)}

      false ->
        %RSAAttachedSignEnvp{ctx | info: Map.put_new(ctx.info, key, val)}
    end
  end

  def get_info(%RSAAttachedSignEnvp{} = ctx, key), do: ctx.info[key]

  # def append_verified_data(%RSAAttachedSignEnvp{} = ctx, data) when is_list(data) do
  #  %RSAAttachedSignEnvp{ctx | verified_data: data ++ ctx.verified_data}
  # end

  # def append_verified_data(%RSAAttachedSignEnvp{} = ctx, data) do
  #  %RSAAttachedSignEnvp{ctx | verified_data: [data | ctx.verified_data]}
  # end
end

defimpl ExCcrypto.Asymkey.AsymkeyVerify, for: ExCcrypto.Asymkey.RSA.RSAAttachedSignEnvp do
  alias ExCcrypto.Asymkey.RSA.RSAAttachedSignEnvp
  alias ExCcrypto.Asymkey.RSA.RSASignContext
  alias ExCcrypto.Asymkey.RSA.RSASignEnvp
  alias ExCcrypto.Asymkey.AsymkeyVerify
  alias ExCcrypto.Asymkey.AsymkeyHelper

  require Logger

  def verify_init(
        %RSAAttachedSignEnvp{
          sign_envp: %RSASignEnvp{sign_context: %RSASignContext{compress_data?: true}}
        } = ctx,
        opts
      ) do
    Logger.debug("Attached verify with compression on")
    verCtx = AsymkeyVerify.verify_init(ctx.sign_envp, opts)
    avCtx = RSAAttachedSignEnvp.set_info(ctx, :verify_context, verCtx)
    z = :zlib.open()
    :zlib.inflateInit(z)

    RSAAttachedSignEnvp.set_info(avCtx, :compress_context, z)
    |> RSAAttachedSignEnvp.set_info(:compression_on?, true)
  end

  def verify_init(%RSAAttachedSignEnvp{} = ctx, opts) do
    Logger.debug("attached verify without compression")
    verCtx = AsymkeyVerify.verify_init(ctx.sign_envp, opts)

    RSAAttachedSignEnvp.set_info(ctx, :verify_context, verCtx)
    |> RSAAttachedSignEnvp.set_info(:compression_on?, false)
  end

  def verify_update(%RSAAttachedSignEnvp{info: %{compression_on?: false}} = ctx, _data) do
    Logger.debug("verify_update without compression")
    Logger.debug("Input data to verify without compression: #{inspect(ctx.data)}")

    RSAAttachedSignEnvp.set_info(
      ctx,
      :verify_context,
      AsymkeyVerify.verify_update(
        RSAAttachedSignEnvp.get_info(ctx, :verify_context),
        ctx.data
      )
    )
  end

  def verify_update(%RSAAttachedSignEnvp{info: %{compression_on?: true}} = ctx, _data) do
    Logger.debug("verify_update with compression turned on")
    dat = :zlib.inflate(RSAAttachedSignEnvp.get_info(ctx, :compress_context), ctx.data)
    Logger.debug("Input data to verify : #{inspect(dat)}")

    RSAAttachedSignEnvp.set_info(
      ctx,
      :verify_context,
      AsymkeyVerify.verify_update(
        RSAAttachedSignEnvp.get_info(ctx, :verify_context),
        dat
      )
    )
  end

  def verify_final(
        %RSAAttachedSignEnvp{sign_envp: %{sign_context: %{attached_mode?: true}}} = ctx,
        _signature
      ) do
    case AsymkeyVerify.verify_final(
           RSAAttachedSignEnvp.get_info(ctx, :verify_context),
           ctx.sign_envp.signature
         ) do
      {:ok, %{verification_result: true} = res} ->
        {:ok,
         Map.put_new(
           res,
           :attached_data,
           RSASignEnvp.get_sign_context(RSAAttachedSignEnvp.get_sign_envp(ctx)).data
         )}

      res ->
        res
    end
  end

  def verify_final(ctx, _signature) do
    AsymkeyVerify.verify_final(
      RSAAttachedSignEnvp.get_info(ctx, :verify_context),
      ctx.sign_envp.signature
    )
  end

  defdelegate verify(ctx, data, signature, opts), to: AsymkeyHelper
end
