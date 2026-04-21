defimpl ExCcrypto.KDF.KDFEncoder, for: ExCcrypto.KDF.BcryptContext do
  alias ExCcrypto.KDF.BcryptContext
  alias ExCcrypto.KDF.KDFEncoder

  def encode(%BcryptContext{} = kdf, :binary, _opts) do
    {:ok, :erlang.term_to_binary(kdf)}
  end

  def encode!(kdf, format, opts) do
    {:ok, val} = KDFEncoder.encode(kdf, format, opts)
    val
  end

  def decode(bin, _opts) do
    try do
      {:ok, :erlang.binary_to_term(bin, [:safe])}
    rescue
      ArgumentError -> {:error, :invalid_encoding}
    end
  end

  def decode!(bin, opts) do
    {:ok, val} = KDFEncoder.decode(bin, opts)
    val
  end
end
