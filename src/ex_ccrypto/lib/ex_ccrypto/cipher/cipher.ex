# Public API
defprotocol ExCcrypto.Cipher do
  @fallback_to_any true
  def cipher_init(ctx, opts \\ nil)

  def cipher_update(ctx, data \\ nil)

  def cipher_final(ctx, opts \\ nil)

  def cipher(ctx, data, opts \\ nil)

  ## this make it interface function to allow
  ## sync with KDF function
  # def get_key_byte_length(ctx)

  ## sync with KDF function or application wishes to set
  ## their own session key without going to each and every
  ## cipher algorithms
  # def set_transient_key(ctx, key)

  # def set_session_data(ctx, key, value)

  # def get_session_data(ctx, key, default \\ nil)

  # def clear_session_data(ctx, key, value \\ nil)
end
