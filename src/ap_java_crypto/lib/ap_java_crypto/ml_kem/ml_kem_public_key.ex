defmodule ApJavaCrypto.MlKem.MlKemPublicKey do
  alias ApJavaCrypto.MlKem.MlKemPublicKey

  use TypedStruct

  typedstruct do
    # 128, 192 or 256
    field(:variant, any())
    field(:format, any(), default: :der)
    field(:value, any())
  end

  def new(variant, privkey, format \\ :der) do
    %MlKemPublicKey{
      variant: variant,
      value: privkey,
      format: format
    }
  end
end

alias ExCcrypto.Asymkey.KeyEncoding
alias ApJavaCrypto.MlKem.MlKemPublicKey

defimpl KeyEncoding, for: MlKemPublicKey do
  def to_native(%MlKemPublicKey{format: :der} = pkey, _opts), do: pkey.value

  def to_native(%MlKemPublicKey{format: format}, _opts),
    do: {:error, {:format_not_supported, format}}

  def to_native!(key, _opts) do
    with {:ok, rk} <- KeyEncoding.to_native(key) do
      rk
    end
  end

  def encode(%MlKemPublicKey{format: :der} = key, :pem, _opts) do
    {:ok,
     "----BEGIN PUBLIC KEY-----\n#{Base.encode64(:erlang.term_to_binary(key))}\n----END PUBLIC KEY-----\n"}
  end

  def encode(%MlKemPublicKey{format: :pem} = key, :der, _opts) do
    val =
      String.replace(key.value, "-----BEGIN PUBLIC KEY-----\n", "")
      |> String.replace("-----END PUBLIC KEY-----", "")

    {:ok, Base.decode64!(val)}
  end

  def encode(%MlKemPublicKey{format: format}, to_format, _opts),
    do: {:error, {:encoding_not_supported, format, to_format}}

  def encode!(%MlKemPublicKey{} = key, format, opts) do
    with {:ok, val} <- encode(key, format, opts) do
      val
    end
  end
end

defimpl ExCcrypto.UniqueKeyIdGenerator, for: MlKemPublicKey do
  require Logger

  def unique_key_id(%MlKemPublicKey{value: val}, _opts) do
    res = :crypto.hash_init(:sha3_256) |> :crypto.hash_update(val) |> :crypto.hash_final()
    Base.hex_encode32(res)
  end
end

defimpl ExCcrypto.ContextConfig, for: MlKemPublicKey do
  def set(ctx, :variant, value, _opts)
      when value in [:ml_kem_512, :ml_kem_768, :ml_kem_1024],
      do: %MlKemPublicKey{ctx | variant: value}

  def set(ctx, :value, value, _opts) do
    %MlKemPublicKey{ctx | value: value}
  end

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, key, _default, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key),
    do: %{}

  def info(_ctx, :setter_key),
    do: %{}

  def info(_ctx, info),
    do: %{error: "Info operation error on KazKemPublicKey. No info key '#{info}' found"}
end
