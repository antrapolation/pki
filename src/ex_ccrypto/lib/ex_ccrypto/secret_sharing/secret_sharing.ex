defprotocol ExCcrypto.SecretSharing do
  def split(ctx, data, opts \\ nil)

  def recover_init(ctx, opts \\ nil)

  def recover_add_share(ctx, share)

  def recover_final(ctx)
end
