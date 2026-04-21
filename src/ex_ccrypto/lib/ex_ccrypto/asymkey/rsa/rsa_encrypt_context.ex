# Public Struct
defmodule ExCcrypto.Asymkey.RSA.RSAEncryptContext do
  alias ExCcrypto.Asymkey.RSA.RSAEncryptContext
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Cipher.CipherContextBuilder
  alias ExCcrypto.Asymkey.KeyEncoding
  use TypedStruct

  require Logger

  typedstruct do
    field(:encryption_keys, List.t(), default: [])
    field(:cipher_context, any(), default: CipherContextBuilder.cipher_context(:aes_256_gcm))
    # field(:kdf_context, any(), default: nil)
  end

  def add_encryption_key(
        ctx,
        key,
        opts \\ %{
          cipher_context: CipherContextBuilder.cipher_context(:aes_256_gcm)
          #      kdf_context: KDFContextBuilder.kdf_context(:argon2)
        }
      )

  def add_encryption_key(ctx, %RSAPublicKey{} = key, opts) do
    %RSAEncryptContext{
      ctx
      | encryption_keys:
          ctx.encryption_keys ++
            [%{recipient_key: KeyEncoding.to_native!(key), opts: opts}]
    }
  end

  def add_encryption_key(_ctx, key, _opts), do: {:error, {:unsupported_encryption_key_type, key}}

  def set_cipher_context(ctx, cc) do
    %{ctx | cipher_context: cc}
  end
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Asymkey.RSA.RSAEncryptContext do
  alias ExCcrypto.Asymkey.RSA.RSAEncryptContext

  def set(ctx, :add_encryption_key, val, _opts),
    do: RSAEncryptContext.add_encryption_key(ctx, val)

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, key, _value, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key) do
    %{
      cipher_context: "Return the cipher context for this RSA cipher operation",
      kdf_context: "Return the KDF config to derive the session key for RSA cipher operation"
    }
  end

  def info(_ctx, :setter_key),
    do: %{
      add_encryption_key: "Add recipient key to construct the RSA cipher envelope"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on RSAEncryptContext. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey.AsymkeyEncrypt, for: ExCcrypto.Asymkey.RSA.RSAEncryptContext do
  alias ExCcrypto.Asymkey.RSA.RSAPublicKey
  alias ExCcrypto.Asymkey.RSA.RSARecpEnvp
  alias ExCcrypto.Asymkey.RSA.RSACipher
  alias ExCcrypto.UniqueKeyIdGenerator
  alias ExCcrypto.Asymkey.AsymkeyEncrypt
  alias ExCcrypto.Cipher

  require Logger

  def encrypt_init(ctx, opts) do
    csess = Cipher.cipher_init(ctx.cipher_context, opts)
    Map.put_new(ctx, :cipher_session, csess)
  end

  def encrypt_update(ctx, data) do
    %{ctx | cipher_session: Cipher.cipher_update(ctx.cipher_session, data)}
  end

  def encrypt_final(ctx, opts) do
    {:ok, %{cipher: cipher, cipher_context: cipher_ctx, transient_key: key}} =
      Cipher.cipher_final(ctx.cipher_session, opts)

    recp_envp =
      for recp <- ctx.encryption_keys do
        encrypt_for_recipient(
          recp,
          key
        )
      end

    {:ok,
     %RSACipher{}
     |> RSACipher.set_cipher(cipher)
     |> RSACipher.set_recp_envp(recp_envp)
     |> RSACipher.set_cipher_context(cipher_ctx)}
  end

  def encrypt(ctx, data, opts \\ nil) do
    AsymkeyEncrypt.encrypt_init(ctx, opts)
    |> AsymkeyEncrypt.encrypt_update(data)
    |> AsymkeyEncrypt.encrypt_final(opts)
  end

  defp encrypt_for_recipient(recp, data) do
    %{recipient_key: recpKey} = recp

    cipher = :public_key.encrypt_public(data, recpKey)

    RSARecpEnvp.encap(
      UniqueKeyIdGenerator.unique_key_id(RSAPublicKey.to_RSA_public_key(:native, recpKey)),
      cipher
    )
  end
end
