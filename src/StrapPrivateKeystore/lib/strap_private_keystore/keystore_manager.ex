defprotocol StrapPrivateKeystore.KeystoreManager do
  def keystore_to_keypair(keystore, auth_token, opts \\ %{})

  def update_keystore_auth_token(keystore, existing_auth_token, new_auth_token, opts \\ %{})
end
