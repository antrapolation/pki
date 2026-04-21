# Public Struct
defmodule ExCcrypto.Asymkey.Ecc.EccAttachedSignEnvp do
  alias ExCcrypto.Asymkey.Ecc.EccAttachedSignEnvp
  alias ExCcrypto.Asymkey.Ecc.EccSignEnvp
  use TypedStruct

  typedstruct do
    field(:data, any())
    field(:sign_envp, EccSignEnvp.t())
    field(:info, map(), default: %{})
    # field(:verified_data, any(), default: [])
  end

  def set_data(%EccAttachedSignEnvp{} = ctx, val), do: %EccAttachedSignEnvp{ctx | data: val}

  def get_data(%EccAttachedSignEnvp{} = ctx), do: ctx.data

  def set_sign_envp(%EccAttachedSignEnvp{} = ctx, %EccSignEnvp{} = val),
    do: %EccAttachedSignEnvp{ctx | sign_envp: val}

  def get_sign_envp(%EccAttachedSignEnvp{} = ctx), do: ctx.sign_envp

  def set_info(ctx, key, val) do
    case Map.has_key?(ctx.info, key) do
      true ->
        %EccAttachedSignEnvp{ctx | info: Map.put(ctx.info, key, val)}

      false ->
        %EccAttachedSignEnvp{ctx | info: Map.put_new(ctx.info, key, val)}
    end
  end

  def get_info(%EccAttachedSignEnvp{} = ctx, key), do: ctx.info[key]

  # def append_verified_data(%EccAttachedSignEnvp{} = ctx, data) when is_list(data) do
  #  %EccAttachedSignEnvp{ctx | verified_data: data ++ ctx.verified_data}
  # end

  # def append_verified_data(%EccAttachedSignEnvp{} = ctx, data) do
  #  %EccAttachedSignEnvp{ctx | verified_data: [data | ctx.verified_data]}
  # end
end

defimpl ExCcrypto.Asymkey.AsymkeyVerify, for: ExCcrypto.Asymkey.Ecc.EccAttachedSignEnvp do
  alias ExCcrypto.Asymkey.Ecc.EccSignContext
  alias ExCcrypto.Asymkey.Ecc.EccSignEnvp
  alias ExCcrypto.Asymkey.AsymkeyVerify
  alias ExCcrypto.Asymkey.AsymkeyHelper
  alias ExCcrypto.Asymkey.Ecc.EccAttachedSignEnvp

  require Logger

  def verify_init(
        %EccAttachedSignEnvp{
          sign_envp: %EccSignEnvp{sign_context: %EccSignContext{compress_data?: true}}
        } = ctx,
        opts
      ) do
    Logger.debug("Attached verify with compression on")
    verCtx = AsymkeyVerify.verify_init(ctx.sign_envp, opts)
    avCtx = EccAttachedSignEnvp.set_info(ctx, :verify_context, verCtx)
    z = :zlib.open()
    :zlib.inflateInit(z)

    EccAttachedSignEnvp.set_info(avCtx, :compress_context, z)
    |> EccAttachedSignEnvp.set_info(:compression_on?, true)
  end

  def verify_init(%EccAttachedSignEnvp{} = ctx, opts) do
    Logger.debug("attached verify without compression")
    verCtx = AsymkeyVerify.verify_init(ctx.sign_envp, opts)

    EccAttachedSignEnvp.set_info(ctx, :verify_context, verCtx)
    |> EccAttachedSignEnvp.set_info(:compression_on?, false)
  end

  def verify_update(%EccAttachedSignEnvp{info: %{compression_on?: false}} = ctx, _data) do
    Logger.debug("verify_update without compression")
    Logger.debug("Input data to verify without compression: #{inspect(ctx.data)}")

    EccAttachedSignEnvp.set_info(
      ctx,
      :verify_context,
      AsymkeyVerify.verify_update(
        EccAttachedSignEnvp.get_info(ctx, :verify_context),
        ctx.data
      )
    )
  end

  def verify_update(%EccAttachedSignEnvp{info: %{compression_on?: true}} = ctx, _data) do
    Logger.debug("verify_update with compression turned on")
    dat = :zlib.inflate(EccAttachedSignEnvp.get_info(ctx, :compress_context), ctx.data)
    Logger.debug("Input data to verify : #{inspect(dat)}")

    EccAttachedSignEnvp.set_info(
      ctx,
      :verify_context,
      AsymkeyVerify.verify_update(
        EccAttachedSignEnvp.get_info(ctx, :verify_context),
        dat
      )
    )
  end

  def verify_final(
        %EccAttachedSignEnvp{sign_envp: %{sign_context: %{attached_mode?: true}}} = ctx,
        _signature
      ) do
    case AsymkeyVerify.verify_final(
           EccAttachedSignEnvp.get_info(ctx, :verify_context),
           ctx.sign_envp.signature
         ) do
      {:ok, %{verification_result: true} = res} ->
        {:ok,
         Map.put_new(
           res,
           :attached_data,
           EccSignEnvp.get_sign_context(EccAttachedSignEnvp.get_sign_envp(ctx)).data
         )}

      res ->
        res
    end
  end

  def verify_final(ctx, _signature) do
    AsymkeyVerify.verify_final(
      EccAttachedSignEnvp.get_info(ctx, :verify_context),
      ctx.sign_envp.signature
    )
  end

  defdelegate verify(ctx, data, signature, opts), to: AsymkeyHelper
end
