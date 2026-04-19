defmodule PkiCaEngine.CeremonyPassword do
  @moduledoc """
  Encrypts/decrypts custodian passwords for storage in the DB during ceremony preparation.

  Passwords are encrypted with AES-256-GCM using a key derived from SECRET_KEY_BASE.
  They are stored temporarily in the threshold_shares table and wiped after keygen
  completes (or fails). This allows passwords to survive server restarts within
  the ceremony time window.
  """

  @aad "ceremony_custodian_password"

  def encrypt(password) when is_binary(password) do
    key = derive_key()
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, password, @aad, true)
    {:ok, iv <> tag <> ciphertext}
  end

  def decrypt(<<iv::binary-12, tag::binary-16, ciphertext::binary>>) do
    key = derive_key()
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, @aad, tag, false) do
      :error -> {:error, :decryption_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  def decrypt(nil), do: {:error, :no_password}
  def decrypt(_), do: {:error, :invalid_format}

  defp derive_key do
    secret = Application.get_env(:pki_tenant_web, :secret_key_base) ||
             Application.get_env(:pki_ca_engine, :secret_key_base) ||
             System.get_env("SECRET_KEY_BASE") ||
             raise "SECRET_KEY_BASE not configured"

    :crypto.hash(:sha256, "ceremony_password_key:" <> secret)
  end
end
