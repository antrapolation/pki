defmodule ApJavaCrypto.SlhDsa.SlhDsaPrivateKey do
  alias ApJavaCrypto.SlhDsa.SlhDsaPrivateKey

  use TypedStruct

  typedstruct do
    field(:variant, any())
    field(:format, any(), default: :der)
    field(:value, any())
  end

  def new(variant, privkey, format \\ :der) do
    %SlhDsaPrivateKey{
      variant: variant,
      value: privkey,
      format: format
    }
  end
end

alias ApJavaCrypto.SlhDsa.SlhDsaPrivateKey

defimpl ExCcrypto.Asymkey.KeyEncoding, for: SlhDsaPrivateKey do
  # to_native
  def to_native(%SlhDsaPrivateKey{format: :der} = key, _opts), do: {:ok, key.value}

  def to_native(%SlhDsaPrivateKey{format: format}, _opts),
    do: {:error, {:format_not_supported, format}}

  # to_native!
  def to_native!(key, opts) do
    with {:ok, native} <- to_native(key, opts) do
      native
    end
  end

  # der -> der
  def encode(%SlhDsaPrivateKey{format: :der} = key, :der, _opts), do: {:ok, key}

  def encode(%SlhDsaPrivateKey{format: :der} = key, :pem, _opts) do
    {:ok,
     %SlhDsaPrivateKey{
       variant: key.variant,
       format: :pem,
       value:
         "----BEGIN PRIVATE KEY-----\n#{Base.encode64(:erlang.term_to_binary(key))}\n----END PRIVATE KEY-----\n"
     }}
  end

  def encode(%SlhDsaPrivateKey{format: :pem} = key, :der, _opts) do
    val =
      String.replace(key.value, "-----BEGIN PRIVATE KEY-----\n", "")
      |> String.replace("-----END PRIVATE KEY-----", "")

    {:ok, %SlhDsaPrivateKey{variant: key.variant, format: :der, value: Base.decode64!(val)}}
  end

  # der -> native
  # def encode(%SlhDsaPrivateKey{format: :der} = key, :native, _opts) do
  #  with {:ok, der} <- X509.PrivateKey.from_der(key.value) do
  #    {:ok, %SlhDsaPrivateKey{format: :native, value: der}}
  #  end
  # end

  ## pem -> native
  # def encode(%SlhDsaPrivateKey{format: :pem} = key, :native, _opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
  #    {:ok, %SlhDsaPrivateKey{format: :native, value: native}}
  #  end
  # end

  # def encode(%SlhDsaPrivateKey{format: :spem} = key, :native, opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
  #    {:ok, %SlhDsaPrivateKey{format: :native, value: native}}
  #  else
  #    {:error, :malformed} -> {:error, :password_incorrect}
  #  end
  # end

  # def encode(%SlhDsaPrivateKey{format: :native} = key, :pem, nil) do
  #  {:ok, %SlhDsaPrivateKey{format: :pem, value: X509.PrivateKey.to_pem(key.value)}}
  # end

  # def encode(%SlhDsaPrivateKey{format: :native} = key, :pem, opts) do
  #  {:ok, %SlhDsaPrivateKey{format: :spem, value: X509.PrivateKey.to_pem(key.value, opts)}}
  # end

  # def encode(%SlhDsaPrivateKey{format: :native} = key, :der, _opts) do
  #  {:ok, %SlhDsaPrivateKey{format: :der, value: X509.PrivateKey.to_der(key.value)}}
  # end

  def encode!(%SlhDsaPrivateKey{} = key, format, opts) do
    with {:ok, val} <- encode(key, format, opts) do
      val
    end
  end
end
