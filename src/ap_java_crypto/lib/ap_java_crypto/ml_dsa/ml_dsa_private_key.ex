defmodule ApJavaCrypto.MlDsa.MlDsaPrivateKey do
  alias ApJavaCrypto.MlDsa.MlDsaPrivateKey

  use TypedStruct

  typedstruct do
    field(:variant, any())
    field(:format, any(), default: :der)
    field(:value, any())
  end

  def new(variant, privkey, format \\ :der) do
    %MlDsaPrivateKey{
      variant: variant,
      value: privkey,
      format: format
    }
  end
end

alias ApJavaCrypto.MlDsa.MlDsaPrivateKey

defimpl ExCcrypto.Asymkey.KeyEncoding, for: MlDsaPrivateKey do
  # to_native
  def to_native(%MlDsaPrivateKey{format: :der} = key, _opts), do: {:ok, key.value}

  def to_native(%MlDsaPrivateKey{format: format}, _opts),
    do: {:error, {:format_not_supported, format}}

  # to_native!
  def to_native!(key, opts) do
    with {:ok, native} <- to_native(key, opts) do
      native
    end
  end

  # der -> der
  def encode(%MlDsaPrivateKey{format: :der} = key, :der, _opts), do: {:ok, key}

  def encode(%MlDsaPrivateKey{format: :der} = key, :pem, _opts) do
    {:ok,
     %MlDsaPrivateKey{
       variant: key.variant,
       format: :pem,
       value:
         "----BEGIN PRIVATE KEY-----\n#{Base.encode64(:erlang.term_to_binary(key))}\n----END PRIVATE KEY-----\n"
     }}
  end

  def encode(%MlDsaPrivateKey{format: :pem} = key, :der, _opts) do
    val =
      String.replace(key.value, "-----BEGIN PRIVATE KEY-----\n", "")
      |> String.replace("-----END PRIVATE KEY-----", "")

    {:ok, %MlDsaPrivateKey{variant: key.variant, format: :der, value: Base.decode64!(val)}}
  end

  # der -> native
  # def encode(%MlDsaPrivateKey{format: :der} = key, :native, _opts) do
  #  with {:ok, der} <- X509.PrivateKey.from_der(key.value) do
  #    {:ok, %MlDsaPrivateKey{format: :native, value: der}}
  #  end
  # end

  ## pem -> native
  # def encode(%MlDsaPrivateKey{format: :pem} = key, :native, _opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
  #    {:ok, %MlDsaPrivateKey{format: :native, value: native}}
  #  end
  # end

  # def encode(%MlDsaPrivateKey{format: :spem} = key, :native, opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
  #    {:ok, %MlDsaPrivateKey{format: :native, value: native}}
  #  else
  #    {:error, :malformed} -> {:error, :password_incorrect}
  #  end
  # end

  # def encode(%MlDsaPrivateKey{format: :native} = key, :pem, nil) do
  #  {:ok, %MlDsaPrivateKey{format: :pem, value: X509.PrivateKey.to_pem(key.value)}}
  # end

  # def encode(%MlDsaPrivateKey{format: :native} = key, :pem, opts) do
  #  {:ok, %MlDsaPrivateKey{format: :spem, value: X509.PrivateKey.to_pem(key.value, opts)}}
  # end

  # def encode(%MlDsaPrivateKey{format: :native} = key, :der, _opts) do
  #  {:ok, %MlDsaPrivateKey{format: :der, value: X509.PrivateKey.to_der(key.value)}}
  # end

  def encode!(%MlDsaPrivateKey{} = key, format, opts) do
    with {:ok, val} <- encode(key, format, opts) do
      val
    end
  end
end
