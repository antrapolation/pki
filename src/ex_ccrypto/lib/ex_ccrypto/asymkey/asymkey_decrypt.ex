# Public API
defprotocol ExCcrypto.Asymkey.AsymkeyDecrypt do
  def decrypt_init(ctx, public_key, private_key, opts \\ nil)

  def decrypt_update(ctx, data)

  def decrypt_final(ctx, opts \\ nil)

  def decrypt(ctx, public_key, private_key, data, opts \\ nil)
end
