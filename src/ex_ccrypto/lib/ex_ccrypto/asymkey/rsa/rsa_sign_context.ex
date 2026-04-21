# Public Struct
defmodule ExCcrypto.Asymkey.RSA.RSASignContext do
  alias ExCcrypto.Asymkey.RSA.RSASignContext
  alias ExCcrypto.Asymkey.RSA.RSAPrivateKey
  alias ExCcrypto.Asymkey.KeyEncoding
  use TypedStruct

  require Logger

  typedstruct do
    field(:digest_algo, atom(), default: :sha512)
    field(:pre_sign_digest_algo, any())
    field(:private_key, RSAPrivateKey.t())
    field(:keysize, atom())
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
    %RSASignContext{ctx | pre_sign_digest_algo: dgst}
  end

  def set_private_key(ctx, privKey), do: %RSASignContext{ctx | private_key: privKey}

  def get_digest_algo(ctx), do: ctx.digest_algo
  def get_pre_sign_digest_algo(ctx), do: ctx.pre_sign_digest_algo
  def get_private_key(ctx), do: ctx.private_key

  def set_attached_mode(ctx), do: %{ctx | attached_mode?: true}
  def is_attached_mode?(ctx), do: ctx.attached_mode? == true

  def set_detached_mode(ctx), do: %{ctx | attached_mode?: false}
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Asymkey.RSA.RSASignContext do
  alias ExCcrypto.Asymkey.RSA.RSASignContext
  def get(ctx, :private_key, _def, _opts), do: RSASignContext.get_private_key(ctx)
  def get(ctx, :digest_algo, _def, _opts), do: RSASignContext.get_digest_algo(ctx)

  def get(ctx, :pre_sign_digest_algo, _def, _opts),
    do: RSASignContext.get_pre_sign_digest_algo(ctx)

  def get(ctx, :is_attached_mode?, _def, _opts), do: RSASignContext.is_attached_mode?(ctx)
  def get(ctx, :attached_data, _def, _opts), do: ctx.attach_data

  def get(_ctx, key, _def, _opts), do: {:error, {:unsupported_getter_key, key}}

  def set(ctx, :private_key, value, _opts), do: RSASignContext.set_private_key(ctx, value)
  def set(ctx, :digest_algo, value, _opts), do: RSASignContext.set_digest_algo(ctx, value)

  def set(ctx, :pre_sign_digest_algo, value, _opts),
    do: RSASignContext.set_pre_sign_digest_algo(ctx, value)

  def set(ctx, :enable_attached_mode, true, _opts), do: RSASignContext.set_attached_mode(ctx)
  def set(ctx, :enable_attached_mode, false, _opts), do: RSASignContext.set_detached_mode(ctx)

  def set(ctx, :enable_attached_data_compression, value, _opts) when is_boolean(value),
    do: %RSASignContext{ctx | compress_data?: value}

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
    do: %{error: "Info operation error on RSASignContext. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey.AsymkeySign, for: ExCcrypto.Asymkey.RSA.RSASignContext do
  alias ExCcrypto.Asymkey.RSA.RSAAttachedSignEnvp
  alias ExCcrypto.Asymkey.RSA.RSASignEnvp
  alias ExCcrypto.Asymkey.RSA.RSASignContext
  alias ExCcrypto.Asymkey.AsymkeySign
  alias ExCcrypto.Asymkey.KeyEncoding

  require Logger

  def sign_init(%RSASignContext{pre_sign_digest_algo: dgst_algo} = ctx, _opts)
      when not is_nil(dgst_algo) do
    dgst = :crypto.hash_init(dgst_algo)

    init_compress(%RSASignContext{
      ctx
      | pre_sign_digest_context: dgst,
        data: [],
        attached_data: []
    })
  end

  def sign_init(%RSASignContext{} = ctx, _opts) do
    init_compress(%RSASignContext{ctx | data: [], attached_data: []})
  end

  defp init_compress(%RSASignContext{attached_mode?: true, compress_data?: true} = ctx) do
    Logger.debug("attached sign with compressed data")
    z = :zlib.open()
    :zlib.deflateInit(z)
    %RSASignContext{ctx | compress_context: z}
  end

  defp init_compress(ctx), do: ctx

  def sign_update(%RSASignContext{pre_sign_digest_context: dgst_ctx} = ctx, data)
      when not is_nil(dgst_ctx) do
    Logger.debug("sign_update with pre_sign_digest_algo set")

    attach_data(
      %RSASignContext{
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
  def sign_update(%RSASignContext{attached_mode?: true} = ctx, data) do
    Logger.debug("sign_update raw attached")

    actx =
      attach_data(
        ctx,
        data
      )

    %RSASignContext{actx | data: actx.data ++ data}
  end

  def sign_update(%RSASignContext{attached_mode?: false} = ctx, data) do
    Logger.debug("sign_update raw detached")
    %RSASignContext{ctx | data: ctx.data ++ data}
  end

  # defp attach_data(%RSASignContext{attached_mode?: true, compress_data?: false} = ctx, data) do
  defp attach_data(%RSASignContext{compress_data?: false} = ctx, data) do
    Logger.debug("attached sign without compression")
    %RSASignContext{ctx | attached_data: ctx.attached_data ++ data}
  end

  # defp attach_data(%RSASignContext{attached_mode?: true, compress_data?: true} = ctx, data) do
  defp attach_data(%RSASignContext{compress_data?: true} = ctx, data) do
    Logger.debug("attached sign with data compression")

    %RSASignContext{
      ctx
      | attached_data: ctx.attached_data ++ :zlib.deflate(ctx.compress_context, data)
    }
  end

  defp attach_data(ctx, _data), do: ctx

  # def sign_final(%RSASignContext{} = ctx, data) when not is_nil(data) do
  #  sign_update(ctx, data)
  #  sign_final(ctx, nil)
  # end

  def sign_final(%RSASignContext{attached_mode?: true} = ctx, _) do
    {:ok, fctx} = finalize_compress(ctx)

    {:ok, signRes, fctx} = finalize_signing(fctx)

    envp =
      %RSASignEnvp{}
      |> RSASignEnvp.set_signature(signRes)
      |> RSASignEnvp.set_sign_context(%RSASignContext{
        fctx
        | private_key: nil,
          pre_sign_digest_context: nil
      })

    {:ok,
     %RSAAttachedSignEnvp{}
     |> RSAAttachedSignEnvp.set_sign_envp(envp)
     |> RSAAttachedSignEnvp.set_data(fctx.attached_data)}
  end

  def sign_final(%RSASignContext{attached_mode?: false} = ctx, _) do
    {:ok, signRes, ctx} = finalize_signing(ctx)

    {:ok,
     %RSASignEnvp{}
     |> RSASignEnvp.set_signature(signRes)
     |> RSASignEnvp.set_sign_context(%RSASignContext{
       ctx
       | private_key: nil,
         pre_sign_digest_context: nil
     })}
  end

  defp finalize_signing(%RSASignContext{pre_sign_digest_context: dgst_ctx, data: data} = ctx)
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

  defp finalize_signing(%RSASignContext{data: data} = ctx) do
    Logger.debug("Signing data : #{inspect(data)}")

    signRes =
      :public_key.sign(
        data,
        ctx.digest_algo,
        KeyEncoding.to_native!(ctx.private_key)
      )

    {:ok, signRes, ctx}
  end

  defp finalize_compress(%RSASignContext{compress_data?: true} = ctx) do
    fctx = %RSASignContext{
      ctx
      | attached_data:
          :erlang.list_to_binary(
            ctx.attached_data ++ :zlib.deflate(ctx.compress_context, [], :finish)
          )
    }

    :zlib.close(ctx.compress_context)
    {:ok, %RSASignContext{fctx | compress_context: nil}}
  end

  defp finalize_compress(ctx), do: {:ok, ctx}

  def sign(ctx, data, _opts) do
    AsymkeySign.sign_init(ctx)
    |> AsymkeySign.sign_update(data)
    |> AsymkeySign.sign_final(ctx)
  end
end
