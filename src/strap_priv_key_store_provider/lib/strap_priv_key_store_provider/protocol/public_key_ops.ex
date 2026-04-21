defprotocol StrapPrivKeyStoreProvider.Protocol.PublicKeyOps do
  @doc """
  Verify data with a keypair.
  """
  def verify_data(keypair, data, signature, opts \\ %{})

  @doc """
  Encrypt data with a keypair.
  """
  def encrypt_data(keypair, data, opts \\ %{})
end
