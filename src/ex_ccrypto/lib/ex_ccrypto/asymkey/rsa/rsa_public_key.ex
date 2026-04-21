defmodule ExCcrypto.Asymkey.RSA.RSAPublicKey do
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  require X509.ASN1
  use TypedStruct

  @type supported_format :: :der | :native | :pem
  typedstruct do
    field(:format, supported_format())
    field(:value, any())
  end

  def encap(pubkey, format \\ :native) do
    %RSAPublicKey{format: format, value: pubkey}
  end

  def from_certificate(X509.ASN1.otp_certificate() = cert) do
    %RSAPublicKey{format: :native, value: X509Certificate.public_key(cert)}
  end

  def to_RSA_public_key(format, value) do
    %RSAPublicKey{format: format, value: value}
  end
end

alias ExCcrypto.Asymkey.KeyEncoding

defimpl KeyEncoding, for: ExCcrypto.Asymkey.RSA.RSAPublicKey do
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey

  def to_native(%RSAPublicKey{format: :native} = key, _opts), do: {:ok, key.value}

  def to_native(%RSAPublicKey{format: :der} = key, _opts) do
    {:ok, native} = X509.PublicKey.from_der(key.value)
    native
  end

  def to_native(%RSAPublicKey{format: :pem} = key, _opts) do
    {:ok, native} = X509.PublicKey.from_pem(key.value)
    native
  end

  def to_native!(key, _opts) do
    {:ok, rk} = KeyEncoding.to_native(key)
    rk
  end

  def encode(%RSAPublicKey{format: format} = key, to_format, opts) when format != :native do
    encode(KeyEncoding.to_native!(key), to_format, opts)
  end

  def encode(%RSAPublicKey{format: :native} = key, :native, _opts), do: {:ok, key}

  def encode(%RSAPublicKey{format: :native} = key, :der, _opts),
    do: {:ok, X509.PublicKey.to_der(key.value)}

  def encode(%RSAPublicKey{format: :native} = key, :pem, _opts),
    do: {:ok, X509.PublicKey.to_pem(key.value)}

  def encode!(%RSAPublicKey{} = key, format, opts) do
    {:ok, val} = encode(key, format, opts)
    val
  end
end

defimpl ExCcrypto.UniqueKeyIdGenerator, for: ExCcrypto.Asymkey.RSA.RSAPublicKey do
  def unique_key_id(ctx, _opts) do
    KeyEncoding.encode!(ctx, :der)
  end
end
