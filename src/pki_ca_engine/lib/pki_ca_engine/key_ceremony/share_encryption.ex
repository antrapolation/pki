defmodule PkiCaEngine.KeyCeremony.ShareEncryption do
  @moduledoc """
  Encrypts/decrypts Shamir shares with custodian passwords.
  Uses PBKDF2-SHA256 for key derivation + AES-256-GCM for encryption.

  Binary format: salt (16 bytes) || iv (12 bytes) || tag (16 bytes) || ciphertext
  """

  @salt_bytes 16
  @iv_bytes 12
  @tag_bytes 16
  @key_bytes 32
  @pbkdf2_iterations 100_000

  @doc """
  Encrypts a binary share with a password string.
  Returns `{:ok, encrypted_binary}` where the binary contains salt, IV, tag, and ciphertext.
  """
  @spec encrypt_share(binary(), binary()) :: {:ok, binary()}
  def encrypt_share(share, password) when is_binary(share) and is_binary(password) do
    salt = :crypto.strong_rand_bytes(@salt_bytes)
    key = :crypto.pbkdf2_hmac(:sha256, password, salt, @pbkdf2_iterations, @key_bytes)
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, share, <<>>, true)

    {:ok, salt <> iv <> tag <> ciphertext}
  end

  @doc """
  Decrypts an encrypted share with a password.
  Returns `{:ok, original_share}` on success, `{:error, :decryption_failed}` on wrong password.
  """
  @spec decrypt_share(binary(), binary()) ::
          {:ok, binary()} | {:error, :decryption_failed} | {:error, :invalid_data}
  def decrypt_share(encrypted, password) when is_binary(encrypted) and is_binary(password) do
    min_size = @salt_bytes + @iv_bytes + @tag_bytes

    if byte_size(encrypted) < min_size do
      {:error, :invalid_data}
    else
      <<salt::binary-size(@salt_bytes), iv::binary-size(@iv_bytes), tag::binary-size(@tag_bytes),
        ciphertext::binary>> = encrypted

      key = :crypto.pbkdf2_hmac(:sha256, password, salt, @pbkdf2_iterations, @key_bytes)

      case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, <<>>, tag, false) do
        :error -> {:error, :decryption_failed}
        plaintext -> {:ok, plaintext}
      end
    end
  end
end
