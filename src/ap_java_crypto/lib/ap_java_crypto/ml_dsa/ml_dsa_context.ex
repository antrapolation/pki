defmodule ApJavaCrypto.MlDsa.MlDsaContext do
  alias ExCcrypto.Asymkey.AsymkeySign
  use TypedStruct

  typedstruct do
    field(:private_key, MlDsaPrivateKey.t())
    field(:digest_algo, any(), default: :sha3_256)
    field(:digest_ctx, any())
  end
end

alias ExCcrypto.Asymkey.AsymkeySign
alias ApJavaCrypto.MlDsa.MlDsaContext

defimpl AsymkeySign, for: MlDsaContext do
  alias ApJavaCrypto.MlDsa.MlDsaEnvp

  def sign_init(%MlDsaContext{} = ctx, _opts) do
    %{ctx | digest_ctx: :crypto.hash_init(ctx.digest_algo)}
  end

  def sign_update(%MlDsaContext{} = ctx, data) do
    %{ctx | digest_ctx: :crypto.hash_update(ctx.digest_ctx, data)}
  end

  def sign_final(ctx, data \\ nil)

  def sign_final(%MlDsaContext{} = ctx, nil) do
    with res <- :crypto.hash_final(ctx.digest_ctx),
         {:ok, signature} =
           ApJavaCrypto.sign(res, {ctx.private_key.variant, :private_key, ctx.private_key.value}) do
      {:ok,
       %MlDsaEnvp{}
       |> MlDsaEnvp.set_signature(signature)
       |> MlDsaEnvp.set_sign_context(ctx)
       |> MlDsaEnvp.sanitize()}
    end
  end

  def sign_final(%MlDsaContext{} = ctx, data), do: sign_update(ctx, data)

  def sign(ctx, data, opts) do
    sign_init(ctx, opts)
    |> sign_update(data)
    |> sign_final()
  end
end

defimpl ExCcrypto.ContextConfig, for: MlDsaContext do
  def get(ctx, :private_key, _def, _opts), do: ctx.private_key
  def get(ctx, :digest_algo, _def, _opts), do: ctx.digest_algo

  # def get(ctx, :is_attached_mode?, _def, _opts), do: EccSignContext.is_attached_mode?(ctx)
  # def get(ctx, :attached_data, _def, _opts), do: ctx.attach_data

  def get(_ctx, key, _def, _opts), do: {:error, {:unsupported_getter_key, key}}

  def set(ctx, :private_key, value, _opts), do: %MlDsaContext{ctx | private_key: value}
  def set(ctx, :digest_algo, value, _opts), do: %MlDsaContext{ctx | digest_algo: value}

  # def set(ctx, :enable_attached_mode, true, _opts), do: EccSignContext.set_attached_mode(ctx)
  # def set(ctx, :enable_attached_mode, false, _opts), do: EccSignContext.set_detached_mode(ctx)

  # def set(ctx, :enable_attached_data_compression, value, _opts) when is_boolean(value),
  #  do: %EccSignContext{ctx | compress_data?: value}

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
    do: %{error: "Info operation error on MlDsaContext. No info key '#{info}' found"}
end
