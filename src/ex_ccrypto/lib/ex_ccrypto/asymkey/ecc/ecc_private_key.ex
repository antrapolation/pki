defmodule ExCcrypto.Asymkey.Ecc.EccPrivateKey do
  use TypedStruct

  @type supported_encoding :: :native | :der | :pem
  typedstruct do
    field(:format, supported_encoding())
    field(:value, any())
  end
end

defimpl ExCcrypto.Asymkey.KeyEncoding, for: ExCcrypto.Asymkey.Ecc.EccPrivateKey do
  alias ExCcrypto.Asymkey.KeyEncodingException
  alias ExCcrypto.Asymkey.Ecc.EccPrivateKey

  # to_native
  def to_native(%EccPrivateKey{format: :native} = key, _opts), do: {:ok, key.value}

  def to_native(%EccPrivateKey{format: :pem} = key, _opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
      {:ok, native}
    end
  end

  def to_native(%EccPrivateKey{format: :spem} = key, opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
      {:ok, native}
    else
      {:error, :malformed} -> {:error, :password_incorrect}
    end
  end

  def to_native(%EccPrivateKey{format: :der} = key, _opts) do
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
  def encode(%EccPrivateKey{format: :native} = key, :native, _opts), do: {:ok, key}

  # der -> native
  def encode(%EccPrivateKey{format: :der} = key, :native, _opts) do
    with {:ok, der} <- X509.PrivateKey.from_der(key.value) do
      {:ok, %EccPrivateKey{format: :native, value: der}}
    end
  end

  # pem -> native
  def encode(%EccPrivateKey{format: :pem} = key, :native, _opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value) do
      {:ok, %EccPrivateKey{format: :native, value: native}}
    end
  end

  def encode(%EccPrivateKey{format: :spem} = key, :native, opts) do
    with {:ok, native} <- X509.PrivateKey.from_pem(key.value, opts) do
      {:ok, %EccPrivateKey{format: :native, value: native}}
    else
      {:error, :malformed} -> {:error, :password_incorrect}
    end
  end

  def encode(%EccPrivateKey{format: :native} = key, :pem, nil) do
    {:ok, %EccPrivateKey{format: :pem, value: X509.PrivateKey.to_pem(key.value)}}
  end

  def encode(%EccPrivateKey{format: :native} = key, :pem, opts) do
    {:ok, %EccPrivateKey{format: :spem, value: X509.PrivateKey.to_pem(key.value, opts)}}
  end

  def encode(%EccPrivateKey{format: :native} = key, :der, _opts) do
    {:ok, %EccPrivateKey{format: :der, value: X509.PrivateKey.to_der(key.value)}}
  end

  def encode!(%EccPrivateKey{} = key, format, opts) do
    {:ok, val} = encode(key, format, opts)
    val
  end
end
