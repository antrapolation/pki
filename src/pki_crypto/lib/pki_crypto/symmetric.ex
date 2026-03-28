defmodule PkiCrypto.Symmetric do
  @moduledoc "AES-256-GCM authenticated encryption."

  def encrypt(plaintext, key) when is_binary(plaintext) and byte_size(key) == 32 do
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, "", true)
    {:ok, iv <> tag <> ciphertext}
  end

  def encrypt(_plaintext, _key), do: {:error, :invalid_key_size}

  def decrypt(<<iv::binary-12, tag::binary-16, ciphertext::binary>>, key) when byte_size(key) == 32 do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false) do
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
      :error -> {:error, :decryption_failed}
    end
  end

  def decrypt(_data, _key), do: {:error, :decryption_failed}
end
