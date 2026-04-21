defprotocol StrapProcReg.RegStore.StrapProcRegStore do
  def start_up(ctx, opts \\ nil)

  def create(ctx, opts \\ nil)
  def destroy(ctx, opts \\ nil)

  # key is assume part of value
  # if key field really needed use opts to pass in
  def save(ctx, purpose, opts \\ nil)

  def delete(ctx, opts \\ nil)

  def find(ctx, opts \\ nil)

  def run(ctx, cond, opts \\ nil)

  def shutdown(ctx, opts \\ nil)
end
