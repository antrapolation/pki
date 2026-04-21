defprotocol StrapPrivKeyStoreProvider.Protocol.CSRGeneratorProtocol do
  def generate(keystore, owner, opts \\ %{})
end
