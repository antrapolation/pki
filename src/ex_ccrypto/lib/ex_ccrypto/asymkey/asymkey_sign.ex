# Public API
defprotocol ExCcrypto.Asymkey.AsymkeySign do
  def sign_init(context, opts \\ nil)
  def sign_update(context, data)
  def sign_final(context, data \\ nil)

  def sign(context, data, opts)
end
