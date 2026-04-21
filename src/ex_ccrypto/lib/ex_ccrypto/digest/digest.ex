# Public API
defprotocol ExCcrypto.Digest do
  def digest_init(ctx, opts \\ nil)

  def digest_update(ctx, data)

  def digest_final(ctx)

  def digest(ctx, data, opts \\ nil)

  def digest_match?(ctx, data, dgst, opts \\ nil)
end
