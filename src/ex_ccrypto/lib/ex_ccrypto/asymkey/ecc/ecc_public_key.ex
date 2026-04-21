defmodule ExCcrypto.Asymkey.Ecc.EccPublicKey do
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey
  require X509.ASN1
  use TypedStruct

  @type supported_format :: :der | :native | :pem
  typedstruct do
    field(:format, supported_format())
    field(:value, any())
  end

  def from_certificate(X509.ASN1.otp_certificate() = cert) do
    %EccPublicKey{format: :native, value: X509Certificate.public_key(cert)}
  end

  def to_ecc_public_key(format, value) do
    %EccPublicKey{format: format, value: value}
  end
end

alias ExCcrypto.Asymkey.KeyEncoding

defimpl KeyEncoding, for: ExCcrypto.Asymkey.Ecc.EccPublicKey do
  alias ExCcrypto.Asymkey.Ecc.EccPublicKey

  def to_native(%EccPublicKey{format: :native} = key, _opts), do: {:ok, key.value}

  def to_native(%EccPublicKey{format: :der} = key, _opts) do
    {:ok, native} = X509.PublicKey.from_der(key.value)
    native
  end

  def to_native(%EccPublicKey{format: :pem} = key, _opts) do
    {:ok, native} = X509.PublicKey.from_pem(key.value)
    native
  end

  def to_native!(key, _opts) do
    {:ok, rk} = KeyEncoding.to_native(key)
    rk
  end

  def encode(%EccPublicKey{format: format} = key, to_format, opts) when format != :native do
    encode(KeyEncoding.to_native!(key), to_format, opts)
  end

  def encode(%EccPublicKey{format: :native} = key, :native, _opts), do: {:ok, key}

  def encode(%EccPublicKey{format: :native} = key, :der, _opts),
    do: {:ok, X509.PublicKey.to_der(key.value)}

  def encode(%EccPublicKey{format: :native} = key, :pem, _opts),
    do: {:ok, X509.PublicKey.to_pem(key.value)}

  def encode!(%EccPublicKey{} = key, format, opts) do
    {:ok, val} = encode(key, format, opts)
    val
  end
end

defimpl ExCcrypto.UniqueKeyIdGenerator, for: ExCcrypto.Asymkey.Ecc.EccPublicKey do
  def unique_key_id(ctx, _opts) do
    KeyEncoding.encode!(ctx, :der)
  end
end
