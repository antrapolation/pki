defmodule ExCcrypto.Cipher.CipherContextBuilder do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.KDF
  alias ExCcrypto.KDF.KDFContextBuilder
  alias ExCcrypto.Cipher.CipherEngine.BlockCipherContext
  alias ExCcrypto.Cipher.CipherEngine.AeadCipherContext
  alias ExCcrypto.Cipher.CipherContextBuilder

  require Logger

  def supported_ciphers() do
    Enum.sort(
      :crypto.supports(:ciphers)
      |> Enum.reject(fn x ->
        cond do
          String.starts_with?(to_string(x), "aes") == true -> false
          String.starts_with?(to_string(x), "chacha20") == true -> false
          String.starts_with?(to_string(x), "blowfish") == true -> false
          true -> true
        end
      end)
    )
  end

  def default_cipher_context(), do: cipher_context(:aes_256_gcm)

  def cipher_context(cipher, opts \\ %{})

  def cipher_context(cipher, opts) do
    sys_supported = CipherContextBuilder.supported_ciphers()

    case Enum.member?(sys_supported, cipher) do
      true ->
        construct_cipher_context(cipher, opts)

      false ->
        {:error, {:cipher_not_supported, cipher}}
    end
  end

  # 
  # Direct convert user given key into encryption key in single operation
  #
  def user_key_cipher_context(
        cipher,
        user_key,
        opts \\ %{kdf_context: KDFContextBuilder.kdf_context(:argon2)}
      )

  def user_key_cipher_context(cipher, user_key, %{kdf_context: kdf} = _opts) do
    cctx = CipherContextBuilder.cipher_context(cipher)

    derived =
      ContextConfig.set(kdf, :out_length, ContextConfig.get(cctx, :key_byte_size))
      |> KDF.derive!(user_key)

    ContextConfig.set(cctx, :session_key, ContextConfig.get(derived, :derived_value))
    |> ContextConfig.set(:user_key_kdf_context, ContextConfig.get(derived, :derivation_context))
  end

  defp construct_cipher_context(cipher, opts) do
    info = :crypto.cipher_info(cipher)

    # Logger.debug("cipher info : #{inspect(info)}")

    construct_context(cipher, info, opts)
  end

  defp construct_context(cipher, %{prop_aead: true} = info, _opts) do
    Logger.debug("constructing aead context")

    %AeadCipherContext{
      keysize: trunc(info.key_length * 8),
      key_byte_size: info.key_length,
      iv_length: info.iv_length,
      mode: info.mode,
      cipher_name: cipher
    }
  end

  defp construct_context(cipher, %{prop_aead: false} = info, _opts) do
    Logger.debug("constructing block context")

    %BlockCipherContext{
      keysize: trunc(info.key_length * 8),
      key_byte_size: info.key_length,
      iv_length: info.iv_length,
      mode: info.mode,
      cipher_name: cipher
    }

    # %BlockCipherContext{}
    # |> BlockCipherContext.set_keysize(info.key_length)
    # |> BlockCipherContext.set_iv_length(info.iv_length)
    # |> BlockCipherContext.set_mode(info.mode)
    # |> BlockCipherContext.set_cipher_name(cipher)
  end
end
