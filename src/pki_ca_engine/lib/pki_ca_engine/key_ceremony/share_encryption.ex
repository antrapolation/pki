defmodule PkiCaEngine.KeyCeremony.ShareEncryption do
  @moduledoc """
  Encrypts/decrypts Shamir shares with custodian passwords.
  Uses PBKDF2-SHA256 for key derivation + AES-256-GCM for encryption.

  Binary format: salt (16 bytes) || iv (12 bytes) || tag (16 bytes) || ciphertext

  ## Share Signatures

  Each encrypted share blob is signed with an HMAC-SHA256 keyed by a
  ceremony-scoped secret derived from the ceremony ID.  The signature covers
  only the `encrypted_share` binary so that any post-ceremony tampering or
  envelope-swap (right share, wrong ceremony) is detectable before the
  expensive AES-GCM decryption attempt.

  `sign_share/2` and `verify_share_signature/3` expose the primitive.
  `decrypt_share_verified/3` is the preferred entry point for reconstruction
  paths — it calls `verify_share_signature/3` first and short-circuits on
  failure.
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

  @doc """
  Signs an `encrypted_share` binary with an HMAC-SHA256 keyed by the
  ceremony ID.  The signing key is derived from an application-level secret
  so that even knowing the ceremony ID is not sufficient to forge a signature.

  Returns a 32-byte HMAC digest.
  """
  @spec sign_share(binary(), String.t()) :: binary()
  def sign_share(encrypted_share, ceremony_id)
      when is_binary(encrypted_share) and is_binary(ceremony_id) do
    signing_key = derive_signing_key(ceremony_id)
    :crypto.mac(:hmac, :sha256, signing_key, encrypted_share)
  end

  @doc """
  Verifies that `signature` was produced by `sign_share/2` for the given
  `encrypted_share` and `ceremony_id`.

  Returns `:ok` when valid, `{:error, :invalid_signature}` otherwise.
  The comparison is constant-time to prevent timing attacks.
  """
  @spec verify_share_signature(binary(), binary(), String.t()) ::
          :ok | {:error, :invalid_signature}
  def verify_share_signature(encrypted_share, signature, ceremony_id)
      when is_binary(encrypted_share) and is_binary(signature) and is_binary(ceremony_id) do
    expected = sign_share(encrypted_share, ceremony_id)

    if constant_time_equal?(expected, signature) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  def verify_share_signature(_encrypted_share, _signature, _ceremony_id),
    do: {:error, :invalid_signature}

  @doc """
  Convenience wrapper: verify the share signature first, then decrypt.

  Returns `{:ok, plaintext}` only when both the signature check and
  AES-GCM authentication pass.  Returns `{:error, :invalid_signature}`
  or `{:error, :decryption_failed}` / `{:error, :invalid_data}` otherwise.
  """
  @spec decrypt_share_verified(binary(), binary(), binary(), String.t()) ::
          {:ok, binary()} | {:error, :invalid_signature} | {:error, :decryption_failed} | {:error, :invalid_data}
  def decrypt_share_verified(encrypted_share, signature, password, ceremony_id) do
    with :ok <- verify_share_signature(encrypted_share, signature, ceremony_id) do
      decrypt_share(encrypted_share, password)
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  # Derives a 32-byte HMAC signing key from the ceremony ID.
  # The application secret is read at call time so it can be overridden in
  # tests without recompilation.
  defp derive_signing_key(ceremony_id) do
    app_secret =
      Application.get_env(:pki_ca_engine, :ceremony_signing_secret, "dev-only-secret")

    :crypto.mac(:hmac, :sha256, app_secret, ceremony_id)
  end

  # Constant-time binary comparison (same length required; mismatched lengths
  # short-circuit immediately but that is acceptable here because HMAC outputs
  # are always 32 bytes on both sides).
  defp constant_time_equal?(a, b) when byte_size(a) != byte_size(b), do: false
  defp constant_time_equal?(a, b) do
    :crypto.hash_equals(a, b)
  end
end
