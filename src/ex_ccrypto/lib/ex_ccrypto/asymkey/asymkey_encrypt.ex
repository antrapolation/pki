# Public API
defprotocol ExCcrypto.Asymkey.AsymkeyEncrypt do
  def encrypt_init(ctx, opts \\ nil)

  def encrypt_update(ctx, data)

  def encrypt_final(ctx, opts \\ nil)

  def encrypt(ctx, data, opts \\ nil)
end
