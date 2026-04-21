defimpl ExCcrypto.KDF.KDFEncoder, for: ExCcrypto.KDF.PBKDF2Context do
  alias ExCcrypto.KDF.PBKDF2Context
  alias ExCcrypto.KDF.KDFEncoder

  def encode(%PBKDF2Context{} = kdf, :binary, _opts) do
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
