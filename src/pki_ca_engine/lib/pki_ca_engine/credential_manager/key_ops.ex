defmodule PkiCaEngine.CredentialManager.KeyOps do
  @moduledoc "Low-level keypair generation, encryption, and decryption for credentials."

  alias PkiCrypto.{Algorithm, Registry, Kdf, Symmetric}

  @doc """
  Generate a credential keypair, encrypt the private key with a password-derived key.
  Returns {:ok, %{public_key, encrypted_private_key, salt}} or {:error, reason}.
  """
  def generate_credential_keypair(algorithm_name, password) when is_binary(password) do
    case Registry.get(algorithm_name) do
      nil ->
        {:error, {:unknown_algorithm, algorithm_name}}

      algo ->
        with {:ok, %{public_key: pub, private_key: priv}} <- Algorithm.generate_keypair(algo),
             salt = Kdf.generate_salt(),
             {:ok, derived_key} <- Kdf.derive_key(password, salt),
             {:ok, encrypted_priv} <- Symmetric.encrypt(priv, derived_key) do
          {:ok, %{public_key: pub, encrypted_private_key: encrypted_priv, salt: salt}}
        end
    end
  end

  @doc "Decrypt a private key using the password and stored salt."
  def decrypt_private_key(encrypted_private_key, salt, password) when is_binary(password) do
    with {:ok, derived_key} <- Kdf.derive_key(password, salt) do
      Symmetric.decrypt(encrypted_private_key, derived_key)
    end
  end

  @doc "Verify that the password can decrypt the private key (proves ownership)."
  def verify_key_ownership(encrypted_private_key, salt, password) do
    case decrypt_private_key(encrypted_private_key, salt, password) do
      {:ok, _key} -> true
      {:error, _} -> false
    end
  end

  @doc "Decrypt private key using a pre-derived session key (no PBKDF2 needed)."
  def decrypt_with_session_key(encrypted_private_key, session_key) when byte_size(session_key) == 32 do
    Symmetric.decrypt(encrypted_private_key, session_key)
  end

  @doc "Re-encrypt a private key with a session key (for fast access during session)."
  def encrypt_for_session(private_key, session_key) when byte_size(session_key) == 32 do
    Symmetric.encrypt(private_key, session_key)
  end
end
