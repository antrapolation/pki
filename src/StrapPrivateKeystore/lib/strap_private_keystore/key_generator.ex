defprotocol StrapPrivateKeystore.KeyGenerator do
  def generate_keypair(privKeystore, opts \\ %{})
end
