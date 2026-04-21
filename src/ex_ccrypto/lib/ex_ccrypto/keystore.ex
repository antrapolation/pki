# Public API
defmodule ExCcrypto.Keystore do
  alias ExCcrypto.Keystore.DefaultKeystore

  defdelegate to_keypairstore(keypair, cert, cert_chain, auth_token, opts \\ %{}),
    to: DefaultKeystore

  defdelegate to_raw_keypairstore(keypair, public_key, auth_token, opts \\ %{}),
    to: DefaultKeystore

  defdelegate to_pkcs12_keystore(keypair, cert, chain, auth_token, opts \\ %{}),
    to: DefaultKeystore

  defdelegate load_pkcs12_keystore(keystore, auth_token, opts \\ %{}), to: DefaultKeystore

  defdelegate load_keystore(keystore_bin, auth_token \\ nil), to: DefaultKeystore
end
