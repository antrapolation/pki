defprotocol StrapPrivateKeystore.KeypairManager do
  def to_keystore(keypair, auth_token, opts \\ %{})

  def set_additional_info(keypair, key, value, opts \\ %{})

  def remove_additional_info(keypair, key, opts \\ %{})

  def get_additional_info(keypair, key, opts \\ %{})

  def public_key(keypair, opts \\ %{})

  def private_key(keypair, opts \\ %{})

  def sign_data(keypair, data, opts \\ %{})

  def verify_data(keypair, data, signature, opts \\ %{})

  def encrypt_data(keypair, data, opts \\ %{})

  def decrypt_data(keypair, cipher, opts \\ %{})

  def delete_keypair(keypair, opts \\ %{})

  def open(keypair, opts \\ %{})

  def open2(keypair, callback, opts \\ %{})

  def close(keypair, opts \\ %{})
end
