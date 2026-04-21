defprotocol StrapPrivKeyStoreProvider.Protocol.KeyGeneratorProtocol do
  @doc """
  Generate a private key.
  """
  def generate_key(type, opts \\ %{})
end
