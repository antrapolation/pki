# Public API
defprotocol ExCcrypto.Asymkey.AsymkeyVerify do
  def verify_init(ctx, opts \\ %{})

  @doc """
  Default data nil to facilitate attached sign
  """
  def verify_update(ctx, data \\ nil)

  @doc """
  Default signature nil is to facilitate attached sign
  """
  def verify_final(ctx, signature \\ nil)

  def verify(ctx, data, signature, opts \\ %{})
end
