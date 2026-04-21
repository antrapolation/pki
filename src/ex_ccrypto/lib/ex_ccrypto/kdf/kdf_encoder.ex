# Public API
defprotocol ExCcrypto.KDF.KDFEncoder do
  def encode(kdf, format, opts \\ nil)

  def encode!(kdf, format, opts \\ nil)

  def decode(bin, opts \\ nil)

  def decode!(bin, opts \\ nil)
end
