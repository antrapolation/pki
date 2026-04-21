# Public API
defprotocol ExCcrypto.KDF do
  def derive(conf, input, opts \\ nil)

  def derive!(conf, input, opts \\ nil)
end
