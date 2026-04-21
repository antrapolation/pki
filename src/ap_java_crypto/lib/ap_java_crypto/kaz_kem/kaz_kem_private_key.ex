defmodule ApJavaCrypto.KazKem.KazKemPrivateKey do
  alias ApJavaCrypto.KazKem.KazKemPrivateKey

  use TypedStruct

  typedstruct do
    field(:variant, any())
    field(:format, any(), default: :der)
    field(:value, any())
  end

  def new(variant, privkey, format \\ :der) do
    %KazKemPrivateKey{
      variant: variant,
      value: privkey,
      format: format
    }
  end
end

alias ApJavaCrypto.KazKem.KazKemPrivateKey

defimpl ExCcrypto.Asymkey.KeyEncoding, for: KazKemPrivateKey do
  # to_native
  def to_native(%KazKemPrivateKey{format: :der} = key, _opts), do: {:ok, key.value}

  def to_native(%KazKemPrivateKey{format: format}, _opts),
    do: {:error, {:format_not_supported, format}}

  # to_native!
  def to_native!(key, opts) do
    with {:ok, native} <- to_native(key, opts) do
      native
    end
  end

  # der -> der
  def encode(%KazKemPrivateKey{format: :der} = key, :der, _opts), do: {:ok, key}

  def encode(%KazKemPrivateKey{format: :der} = key, :pem, _opts) do
    {:ok,
     %KazKemPrivateKey{
       variant: key.variant,
       format: :pem,
       value:
         "----BEGIN PRIVATE KEY-----\n#{Base.encode64(:erlang.term_to_binary(key))}\n----END PRIVATE KEY-----\n"
     }}
  end

  def encode(%KazKemPrivateKey{format: :pem} = key, :der, _opts) do
    val =
      String.replace(key.value, "-----BEGIN PRIVATE KEY-----\n", "")
      |> String.replace("-----END PRIVATE KEY-----", "")

    {:ok, %KazKemPrivateKey{variant: key.variant, format: :der, value: Base.decode64!(val)}}
  end

  # der -> native
  # def encode(%KazKemPrivateKey{format: :der} = key, :native, _opts) do
  #  with {:ok, der} <- X509.PrivateKey.from_der(key.value) do
  #    {:ok, %KazKemPrivateKey{format: :native, value: der}}
  #  end
  # end

  ## pem -> native
  # def encode(%KazKemPrivateKey{format: :pem} = key, :native, _opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
  #    {:ok, %KazKemPrivateKey{format: :native, value: native}}
  #  end
  # end

  # def encode(%KazKemPrivateKey{format: :spem} = key, :native, opts) do
  #  with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
  #    {:ok, %KazKemPrivateKey{format: :native, value: native}}
  #  else
  #    {:error, :malformed} -> {:error, :password_incorrect}
  #  end
  # end

  # def encode(%KazKemPrivateKey{format: :native} = key, :pem, nil) do
  #  {:ok, %KazKemPrivateKey{format: :pem, value: X509.PrivateKey.to_pem(key.value)}}
  # end

  # def encode(%KazKemPrivateKey{format: :native} = key, :pem, opts) do
  #  {:ok, %KazKemPrivateKey{format: :spem, value: X509.PrivateKey.to_pem(key.value, opts)}}
  # end

  # def encode(%KazKemPrivateKey{format: :native} = key, :der, _opts) do
  #  {:ok, %KazKemPrivateKey{format: :der, value: X509.PrivateKey.to_der(key.value)}}
  # end

  def encode!(%KazKemPrivateKey{} = key, format, opts) do
    with {:ok, val} <- encode(key, format, opts) do
      val
    end
  end
end
