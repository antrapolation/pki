defmodule ApJavaCrypto.KazSign.KazSignPrivateKey do
  alias ApJavaCrypto.KazSign.KazSignPrivateKey

  use TypedStruct

  typedstruct do
    field(:variant, any())
    field(:format, any(), default: :der)
    field(:value, any())
  end

  def new(variant, privkey, format \\ :der) do
    %KazSignPrivateKey{
      variant: variant,
      value: privkey,
      format: format
    }
  end
end

alias ApJavaCrypto.KazSign.KazSignPrivateKey

defimpl ExCcrypto.Asymkey.KeyEncoding, for: KazSignPrivateKey do
  # to_native
  def to_native(%KazSignPrivateKey{format: :der} = key, _opts), do: {:ok, key.value}

  def to_native(%KazSignPrivateKey{format: format}, _opts),
    do: {:error, {:format_not_supported, format}}

  # to_native!
  def to_native!(key, opts) do
    with {:ok, native} <- to_native(key, opts) do
      native
    end
  end

  # der -> der
  def encode(%KazSignPrivateKey{format: :der} = key, :der, _opts), do: {:ok, key}

  def encode(%KazSignPrivateKey{format: :der} = key, :pem, _opts) do
    {:ok,
     %KazSignPrivateKey{
       variant: key.variant,
       format: :pem,
       value:
         "----BEGIN PRIVATE KEY-----\n#{Base.encode64(:erlang.term_to_binary(key))}\n----END PRIVATE KEY-----\n"
     }}
  end

  def encode(%KazSignPrivateKey{format: :pem} = key, :der, _opts) do
    val =
      String.replace(key.value, "-----BEGIN PRIVATE KEY-----\n", "")
      |> String.replace("-----END PRIVATE KEY-----", "")

    {:ok, %KazSignPrivateKey{variant: key.variant, format: :der, value: Base.decode64!(val)}}
  end

  # der -> native
  # def encode(%KazSignPrivateKey{format: :der} = key, :native, _opts) do
  #  with {:ok, der} <- X509.PrivateKey.from_der(key.value) do
  #    {:ok, %KazSignPrivateKey{format: :native, value: der}}
  #  end
  # end

  ## pem -> native
  # def encode(%KazSignPrivateKey{format: :pem} = key, :native, _opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
  #    {:ok, %KazSignPrivateKey{format: :native, value: native}}
  #  end
  # end

  # def encode(%KazSignPrivateKey{format: :spem} = key, :native, opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
  #    {:ok, %KazSignPrivateKey{format: :native, value: native}}
  #  else
  #    {:error, :malformed} -> {:error, :password_incorrect}
  #  end
  # end

  # def encode(%KazSignPrivateKey{format: :native} = key, :pem, nil) do
  #  {:ok, %KazSignPrivateKey{format: :pem, value: X509.PrivateKey.to_pem(key.value)}}
  # end

  # def encode(%KazSignPrivateKey{format: :native} = key, :pem, opts) do
  #  {:ok, %KazSignPrivateKey{format: :spem, value: X509.PrivateKey.to_pem(key.value, opts)}}
  # end

  # def encode(%KazSignPrivateKey{format: :native} = key, :der, _opts) do
  #  {:ok, %KazSignPrivateKey{format: :der, value: X509.PrivateKey.to_der(key.value)}}
  # end

  def encode!(%KazSignPrivateKey{} = key, format, opts) do
    with {:ok, val} <- encode(key, format, opts) do
      val
    end
  end
end
