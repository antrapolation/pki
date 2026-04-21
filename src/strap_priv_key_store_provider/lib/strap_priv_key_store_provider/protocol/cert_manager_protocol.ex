defprotocol StrapPrivKeyStoreProvider.Protocol.CertManagerProtocol do
  def generate_cert(keystore, owner, issuer, opts \\ %{})

  def issue_cert(keystore, owner, issuer, opts \\ %{})
end
