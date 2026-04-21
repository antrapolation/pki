defmodule ExCcrypto.Asymkey.RSA.RSAPrivateKey do
  alias ExCcrypto.Asymkey.RSA.RSAPrivateKey
  use TypedStruct

  @type supported_encoding :: :native | :der | :pem
  typedstruct do
    field(:format, supported_encoding())
    field(:value, any())
  end

  def encap(privkey, format \\ :native) do
    %RSAPrivateKey{format: format, value: privkey}
  end
end

defimpl ExCcrypto.Asymkey.KeyEncoding, for: ExCcrypto.Asymkey.RSA.RSAPrivateKey do
  alias ExCcrypto.Asymkey.RSA.RSAPrivateKey
  alias ExCcrypto.Asymkey.KeyEncodingException

  # to_native
  def to_native(%RSAPrivateKey{format: :native} = key, _opts), do: {:ok, key.value}

  def to_native(%RSAPrivateKey{format: :pem} = key, _opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
      {:ok, native}
    end
  end

  def to_native(%RSAPrivateKey{format: :spem} = key, opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
      {:ok, native}
    else
      {:error, :malformed} -> {:error, :password_incorrect}
    end
  end

  def to_native(%RSAPrivateKey{format: :der} = key, _opts) do
    with {:ok, native} <- X509.PrivateKey.from_der(key.value) do
      {:ok, native}
    end
  end

  # to_native!
  def to_native!(key, opts) do
    with {:ok, native} <- to_native(key, opts) do
      native
    else
      _ -> raise KeyEncodingException
    end
  end

  # native -> native
  def encode(%RSAPrivateKey{format: :native} = key, :native, _opts), do: {:ok, key}

  # der -> native
  def encode(%RSAPrivateKey{format: :der} = key, :native, _opts) do
    with {:ok, der} <- X509.PrivateKey.from_der(key.value) do
      {:ok, %RSAPrivateKey{format: :native, value: der}}
    end
  end

  # pem -> native
  def encode(%RSAPrivateKey{format: :pem} = key, :native, _opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
      {:ok, %RSAPrivateKey{format: :native, value: native}}
    end
  end

  def encode(%RSAPrivateKey{format: :spem} = key, :native, opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
      {:ok, %RSAPrivateKey{format: :native, value: native}}
    else
      {:error, :malformed} -> {:error, :password_incorrect}
    end
  end

  def encode(%RSAPrivateKey{format: :native} = key, :pem, nil) do
    {:ok, %RSAPrivateKey{format: :pem, value: X509.PrivateKey.to_pem(key.value)}}
  end

  def encode(%RSAPrivateKey{format: :native} = key, :pem, opts) do
    {:ok, %RSAPrivateKey{format: :spem, value: X509.PrivateKey.to_pem(key.value, opts)}}
  end

  def encode(%RSAPrivateKey{format: :native} = key, :der, _opts) do
    {:ok, %RSAPrivateKey{format: :der, value: X509.PrivateKey.to_der(key.value)}}
  end

  def encode!(%RSAPrivateKey{} = key, format, opts) do
    {:ok, val} = encode(key, format, opts)
    val
  end
end
