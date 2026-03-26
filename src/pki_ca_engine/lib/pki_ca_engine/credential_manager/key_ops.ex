defmodule PkiCaEngine.CredentialManager.KeyOps do
  @moduledoc """
  Low-level keypair generation, encryption, and decryption for credentials.
  Delegates to PkiCrypto.KeyOps for the actual crypto operations.
  """

  defdelegate generate_credential_keypair(algorithm_name, password), to: PkiCrypto.KeyOps
  defdelegate decrypt_private_key(encrypted_private_key, salt, password), to: PkiCrypto.KeyOps
  defdelegate verify_key_ownership(encrypted_private_key, salt, password), to: PkiCrypto.KeyOps
  defdelegate decrypt_with_session_key(encrypted_private_key, session_key), to: PkiCrypto.KeyOps
  defdelegate encrypt_for_session(private_key, session_key), to: PkiCrypto.KeyOps
end
