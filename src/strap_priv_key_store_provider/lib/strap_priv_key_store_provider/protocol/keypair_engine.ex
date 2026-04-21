defprotocol StrapPrivKeyStoreProvider.Protocol.KeypairEngine do
  @doc """
  Get the purpose of a keypair.
  """
  def keypair_purpose(keypair, opts \\ %{})

  @doc """
  Convert a keypair to a keystore.
  """
  def to_keystore(keypair, auth_token, opts \\ %{})

  @doc """
  Set additional information for a keypair.
  """
  def set_keypair_info(keypair, key, value, opts \\ %{})

  @doc """
  Remove additional information for a keypair.
  """
  def remove_keypair_info(keypair, key, opts \\ %{})

  @doc """
  Get additional information for a keypair.
  """
  def get_keypair_info(keypair, key, opts \\ %{})

  @doc """
  Get the public key from a keypair.
  """
  def public_key(keypair, opts \\ %{})

  @doc """
  Get the private key from a keypair.
  """
  def private_key(keypair, opts \\ %{})
end
