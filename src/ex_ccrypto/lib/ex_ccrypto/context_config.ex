# Public API
defprotocol ExCcrypto.ContextConfig do
  def get(ctx, key, default \\ nil, opts \\ nil)
  def set(ctx, key, value, opts \\ nil)

  def info(ctx, scope)
end
