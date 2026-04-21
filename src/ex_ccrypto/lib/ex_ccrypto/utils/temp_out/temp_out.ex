defprotocol ExCcrypto.Utils.TempOut do
  def init(ctx, opts \\ nil)

  def update(ctx, data)

  def final(ctx)
end
