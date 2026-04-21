defprotocol ExCcrypto.Mac do
  def mac_init(ctx, opts \\ nil)

  def mac_update(ctx, data)

  def mac_final(ctx)

  def mac(ctx, data, opts \\ nil)

  def mac_match?(ctx, data, mac_value, opts)
end
