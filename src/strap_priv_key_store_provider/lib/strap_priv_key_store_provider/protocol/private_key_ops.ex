defprotocol StrapPrivKeyStoreProvider.Protocol.PrivateKeyOps do
  @doc """
  Sign data with a keypair.
  """
  def sign_data(privkey, data, opts \\ %{})

  @doc """
  Decrypt data with a keypair.
  """
  def decrypt_data(privkey, pubkey, cipher, opts \\ %{})
end
