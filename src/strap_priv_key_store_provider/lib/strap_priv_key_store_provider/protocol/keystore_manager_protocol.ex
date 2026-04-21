defprotocol StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol do
  @doc """
  Convert a keystore to a keypair.
  """
  def to_keypair(keystore, auth_token, opts \\ %{})

  @doc """
  Update the authentication token of a keystore.
  """
  def update_auth_token(keystore, existing_auth_token, new_auth_token, opts \\ %{})
end
