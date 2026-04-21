defprotocol ExCcrypto.UniqueKeyIdGenerator do
  # 
  # Generate unique code to be inserted into keypair encryption envelope
  #
  def unique_key_id(ctx, opts \\ nil)
end
