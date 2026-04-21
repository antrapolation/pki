# Public Struct
defmodule ExCcrypto.Asymkey.Ecc.EccSignContext do
  alias ExCcrypto.Asymkey.KeyEncoding
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  alias ExCcrypto.Asymkey.Ecc.EccSignContext
  alias ExCcrypto.Asymkey.Ecc.EccPrivateKey
  use TypedStruct

  require Logger

  typedstruct do
    field(:digest_algo, atom(), default: :sha512)
    field(:pre_sign_digest_algo, any())
    field(:private_key, EccPrivateKey.t())
    field(:curve, atom())
    field(:pre_sign_digest_context, any())
    # attached mode config
    field(:attached_mode?, boolean(), default: false)
    field(:compress_data?, boolean(), default: false)
    field(:data, any())
    field(:attached_data, any())
    field(:compress_context, any())
  end

  # digest algo during data signing 
  def set_digest_algo(ctx, dgst), do: %{ctx | digest_algo: dgst}

  # digest algo to convert input data before signing
  # i.e. double digest
  def set_pre_sign_digest_algo(ctx, dgst) do
    %EccSignContext{ctx | pre_sign_digest_algo: dgst}
  end

  def set_private_key(ctx, privKey) do
    {:ECPrivateKey, _, _, namedCurve, _, _} = KeyEncoding.to_native!(privKey)

    with {:ok, curve} <- EccKeypair.oid_to_curve_name(namedCurve) do
      Logger.debug("found curve : #{curve} / #{inspect(namedCurve)}")

      cond do
        curve in [:x25519, :x448] ->
          {:error, {:given_private_key_curve_not_for_signing, curve}}

        # %EccSignContext{ctx | private_key: privKey, curve: curve, can_sign: false}

        true ->
          %EccSignContext{ctx | private_key: privKey, curve: curve}
      end
    end
  end

  def get_digest_algo(ctx), do: ctx.digest_algo
  def get_pre_sign_digest_algo(ctx), do: ctx.pre_sign_digest_algo
  def get_private_key(ctx), do: ctx.private_key

  def set_attached_mode(ctx), do: %{ctx | attached_mode?: true}
  def is_attached_mode?(ctx), do: ctx.attached_mode? == true

  def set_detached_mode(ctx), do: %{ctx | attached_mode?: false}
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Asymkey.Ecc.EccSignContext do
  alias ExCcrypto.Asymkey.Ecc.EccSignContext
  def get(ctx, :private_key, _def, _opts), do: EccSignContext.get_private_key(ctx)
  def get(ctx, :digest_algo, _def, _opts), do: EccSignContext.get_digest_algo(ctx)

  def get(ctx, :pre_sign_digest_algo, _def, _opts),
    do: EccSignContext.get_pre_sign_digest_algo(ctx)

  def get(ctx, :is_attached_mode?, _def, _opts), do: EccSignContext.is_attached_mode?(ctx)
  def get(ctx, :attached_data, _def, _opts), do: ctx.attach_data

  def get(_ctx, key, _def, _opts), do: {:error, {:unsupported_getter_key, key}}

  def set(ctx, :private_key, value, _opts), do: EccSignContext.set_private_key(ctx, value)
  def set(ctx, :digest_algo, value, _opts), do: EccSignContext.set_digest_algo(ctx, value)

  def set(ctx, :pre_sign_digest_algo, value, _opts),
    do: EccSignContext.set_pre_sign_digest_algo(ctx, value)

  def set(ctx, :enable_attached_mode, true, _opts), do: EccSignContext.set_attached_mode(ctx)
  def set(ctx, :enable_attached_mode, false, _opts), do: EccSignContext.set_detached_mode(ctx)

  def set(ctx, :enable_attached_data_compression, value, _opts) when is_boolean(value),
    do: %EccSignContext{ctx | compress_data?: value}

  def set(_ctx, key, _val, _opts), do: {:error, {:unsupported_setter_key, key}}

  def info(_ctx, :getter_key),
    do: %{
      private_key: "Return private key in binary form for this signing operation",
      digest_algo: "Return digest algo used in this signing operation"
    }

  def info(_ctx, :setter_key),
    do: %{
      private_key: "Set private key in binary form for this signing operation",
      digest_algo:
        "Set digest algo in atom used in this signing operation. Valid digest algo can be obtained via DigestContextBuilder.supported_digests()"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on EccSignContext. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey.AsymkeySign, for: ExCcrypto.Asymkey.Ecc.EccSignContext do
  alias ExCcrypto.Asymkey.Ecc.EccAttachedSignEnvp
  alias ExCcrypto.Asymkey.Ecc.EccSignEnvp
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ExCcrypto.Asymkey.Ecc.EccSignContext
  alias ExCcrypto.Asymkey.KeyEncoding

  require Logger

  def sign_init(%EccSignContext{pre_sign_digest_algo: dgst_algo} = ctx, _opts)
      when not is_nil(dgst_algo) do
    dgst = :crypto.hash_init(dgst_algo)

    init_compress(%EccSignContext{
      ctx
      | pre_sign_digest_context: dgst,
        data: [],
        attached_data: []
    })
  end

  def sign_init(%EccSignContext{} = ctx, _opts) do
    init_compress(%EccSignContext{ctx | data: [], attached_data: []})
  end

  defp init_compress(%EccSignContext{attached_mode?: true, compress_data?: true} = ctx) do
    Logger.debug("attached sign with compressed data")
    z = :zlib.open()
    :zlib.deflateInit(z)
    %EccSignContext{ctx | compress_context: z}
  end

  defp init_compress(ctx), do: ctx

  def sign_update(%EccSignContext{pre_sign_digest_context: dgst_ctx} = ctx, data)
      when not is_nil(dgst_ctx) do
    Logger.debug("sign_update with pre_sign_digest_algo set")

    attach_data(
      %EccSignContext{
        ctx
        | pre_sign_digest_context: :crypto.hash_update(dgst_ctx, data)
      },
      data
    )
  end

  # 
  # pre_sign_digest_algo is not given shall fall into here
  # Need to keep the data?
  #
  def sign_update(%EccSignContext{attached_mode?: true} = ctx, data) do
    Logger.debug("sign_update raw attached")

    actx =
      attach_data(
        ctx,
        data
      )

    %EccSignContext{actx | data: actx.data ++ data}
  end

  def sign_update(%EccSignContext{attached_mode?: false} = ctx, data) do
    Logger.debug("sign_update raw detached")
    %EccSignContext{ctx | data: ctx.data ++ data}
  end

  # defp attach_data(%EccSignContext{attached_mode?: true, compress_data?: false} = ctx, data) do
  defp attach_data(%EccSignContext{compress_data?: false} = ctx, data) do
    Logger.debug("attached sign without compression")
    %EccSignContext{ctx | attached_data: ctx.attached_data ++ data}
  end

  # defp attach_data(%EccSignContext{attached_mode?: true, compress_data?: true} = ctx, data) do
  defp attach_data(%EccSignContext{compress_data?: true} = ctx, data) do
    Logger.debug("attached sign with data compression")

    %EccSignContext{
      ctx
      | attached_data: ctx.attached_data ++ :zlib.deflate(ctx.compress_context, data)
    }
  end

  defp attach_data(ctx, _data), do: ctx

  # def sign_final(%EccSignContext{} = ctx, data) when not is_nil(data) do
  #  sign_update(ctx, data)
  #  sign_final(ctx, nil)
  # end

  def sign_final(%EccSignContext{attached_mode?: true} = ctx, _) do
    {:ok, fctx} = finalize_compress(ctx)

    {:ok, signRes, fctx} = finalize_signing(fctx)

    envp =
      %EccSignEnvp{}
      |> EccSignEnvp.set_signature(signRes)
      |> EccSignEnvp.set_sign_context(%EccSignContext{
        fctx
        | private_key: nil,
          pre_sign_digest_context: nil
      })

    {:ok,
     %EccAttachedSignEnvp{}
     |> EccAttachedSignEnvp.set_sign_envp(envp)
     |> EccAttachedSignEnvp.set_data(fctx.attached_data)}
  end

  def sign_final(%EccSignContext{attached_mode?: false} = ctx, _) do
    {:ok, signRes, ctx} = finalize_signing(ctx)

    {:ok,
     %EccSignEnvp{}
     |> EccSignEnvp.set_signature(signRes)
     |> EccSignEnvp.set_sign_context(%EccSignContext{
       ctx
       | private_key: nil,
         pre_sign_digest_context: nil
     })}
  end

  defp finalize_signing(%EccSignContext{pre_sign_digest_context: dgst_ctx, data: data} = ctx)
       when not is_nil(dgst_ctx) do
    dgstRes =
      case not is_nil(data) do
        true ->
          :crypto.hash_update(dgst_ctx, data)
          :crypto.hash_final(dgst_ctx)

        false ->
          :crypto.hash_final(dgst_ctx)
      end

    # dgstRes = :crypto.hash_final(dgst_ctx)

    signRes =
      :public_key.sign(
        dgstRes,
        ctx.digest_algo,
        KeyEncoding.to_native!(ctx.private_key)
      )

    {:ok, signRes, ctx}
  end

  defp finalize_signing(%EccSignContext{data: data} = ctx) do
    Logger.debug("Signing data : #{inspect(data)}")

    signRes =
      :public_key.sign(
        data,
        ctx.digest_algo,
        KeyEncoding.to_native!(ctx.private_key)
      )

    {:ok, signRes, ctx}
  end

  defp finalize_compress(%EccSignContext{compress_data?: true} = ctx) do
    fctx = %EccSignContext{
      ctx
      | attached_data:
          :erlang.list_to_binary(
            ctx.attached_data ++ :zlib.deflate(ctx.compress_context, [], :finish)
          )
    }

    :zlib.close(ctx.compress_context)
    {:ok, %EccSignContext{fctx | compress_context: nil}}
  end

  defp finalize_compress(ctx), do: {:ok, ctx}

  def sign(ctx, data, _opts) do
    AsymkeySign.sign_init(ctx)
    |> AsymkeySign.sign_update(data)
    |> AsymkeySign.sign_final(ctx)
  end
end
