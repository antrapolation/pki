defmodule ApJavaCrypto.MlDsa.MlDsaPublicKey do
  alias ApJavaCrypto.MlDsa.MlDsaPublicKey
  use TypedStruct

  typedstruct do
    # 128, 192 or 256
    field(:variant, any())
    field(:format, any(), default: :der)
    field(:value, any())
  end

  def new(variant, privkey, format \\ :der) do
    %MlDsaPublicKey{
      variant: variant,
      value: privkey,
      format: format
    }
  end
end

alias ExCcrypto.Asymkey.KeyEncoding
alias ApJavaCrypto.MlDsa.MlDsaPublicKey

defimpl KeyEncoding, for: MlDsaPublicKey do
  def to_native(%MlDsaPublicKey{format: :der} = pkey, _opts), do: pkey.value

  def to_native(%MlDsaPublicKey{format: format}, _opts),
    do: {:error, {:format_not_supported, format}}

  def to_native!(key, _opts) do
    with {:ok, rk} <- KeyEncoding.to_native(key) do
      rk
    end
  end

  def encode(%MlDsaPublicKey{format: :der} = key, :pem, _opts) do
    {:ok,
     "----BEGIN PUBLIC KEY-----\n#{Base.encode64(:erlang.term_to_binary(key))}\n----END PUBLIC KEY-----\n"}
  end

  def encode(%MlDsaPublicKey{format: :pem} = key, :der, _opts) do
    val =
      String.replace(key.value, "-----BEGIN PUBLIC KEY-----\n", "")
      |> String.replace("-----END PUBLIC KEY-----", "")

    {:ok, Base.decode64!(val)}
  end

  def encode(%MlDsaPublicKey{format: format}, to_format, _opts),
    do: {:error, {:encoding_not_supported, format, to_format}}

  def encode!(%MlDsaPublicKey{} = key, format, opts) do
    with {:ok, val} <- encode(key, format, opts) do
      val
    end
  end
end
