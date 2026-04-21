defmodule ApJavaCrypto.MlKem.MlKemContext do
  alias ApJavaCrypto.MlKem.MlKemPublicKey
  alias ExCcrypto.KDF.KDFContextBuilder
  alias ExCcrypto.Cipher.CipherContextBuilder
  use TypedStruct

  require Logger

  typedstruct do
    field(:encryption_keys, List.t(), default: [])
    field(:cipher_context, any(), default: CipherContextBuilder.cipher_context(:aes_256_gcm))
    field(:kdf_context, any(), default: nil)
  end

  def add_encryption_key(
        ctx,
        key,
        opts \\ %{
          cipher_context: CipherContextBuilder.cipher_context(:aes_256_gcm),
          kdf_context: KDFContextBuilder.kdf_context(:argon2)
        }
      )

  def add_encryption_key(ctx, %MlKemPublicKey{} = key, opts) do
    %{
      ctx
      | encryption_keys:
          ctx.encryption_keys ++
            [%{recipient_key: key, opts: opts}]
    }
  end

  def add_encryption_key(_ctx, key, _opts), do: {:error, {:unsupported_encryption_key_type, key}}

  def set_cipher_context(ctx, cc) do
    %{ctx | cipher_context: cc}
  end

  def set_kdf_config(ctx, kc) do
    %{ctx | kdf_config: kc}
  end
end

alias ApJavaCrypto.MlKem.MlKemContext

defimpl ExCcrypto.ContextConfig, for: MlKemContext do
  def set(ctx, :add_encryption_key, val, _opts),
    do: MlKemContext.add_encryption_key(ctx, val)

  def set(_ctx, key, _value, _opts), do: {:error, {:setter_key_not_supported, key}}

  def get(_ctx, key, _value, _opts), do: {:error, {:getter_key_not_supported, key}}

  def info(_ctx, :getter_key) do
    %{
      cipher_context: "Return the cipher context for this ML-KEM operation",
      kdf_context: "Return the KDF config to derive the session key for ML-KEM operation"
    }
  end

  def info(_ctx, :setter_key),
    do: %{
      add_encryption_key: "Add recipient key to construct the ML-KEM envelope"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on MLKemContext. No info key '#{info}' found"}
end

defimpl ExCcrypto.Asymkey.AsymkeyEncrypt, for: MlKemContext do
  alias ApJavaCrypto.MlKem.MlKemEnvp
  alias ApJavaCrypto.MlKem.MlKemPublicKey
  alias ApJavaCrypto.MlKem.MlKemCipher
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.UniqueKeyIdGenerator
  alias ExCcrypto.Asymkey.AsymkeyEncrypt
  alias ExCcrypto.KDF
  alias ExCcrypto.Cipher

  require Logger

  def encrypt_init(%MlKemContext{} = ctx, opts) do
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
     %MlKemCipher{}
     |> MlKemCipher.set_cipher(cipher)
     |> MlKemCipher.set_recp_envp(recp_envp)
     |> MlKemCipher.set_cipher_context(cipher_ctx)
     |> MlKemCipher.set_kdf_context(ctx.kdf_context)}
  end

  def encrypt(ctx, data, opts \\ nil) do
    AsymkeyEncrypt.encrypt_init(ctx, opts)
    |> AsymkeyEncrypt.encrypt_update(data)
    |> AsymkeyEncrypt.encrypt_final(opts)
  end

  defp encrypt_for_recipient(recp, key) do
    Logger.debug("recp : #{inspect(recp)}")
    Logger.debug("key : #{inspect(key)}")

    %{recipient_key: recpKey, opts: %{cipher_context: key_cc, kdf_context: key_kc}} = recp

    {:ok, shared_secret, recp_cipher} =
      case recpKey do
        %MlKemPublicKey{} ->
          ApJavaCrypto.encapsulate({recpKey.variant, :public_key, recpKey.value})

        pubkey ->
          raise "Unsupported public key type #{inspect(pubkey)}"
      end

    kdf_output =
      ContextConfig.set(key_kc, :out_length, ContextConfig.get(key_cc, :key_byte_size))
      |> KDF.derive!(shared_secret)

    {:ok, %{cipher: cipher, cipher_context: recpCipherCtx, transient_key: _key}} =
      ContextConfig.set(key_cc, :session_key, ContextConfig.get(kdf_output, :derived_value))
      |> Cipher.cipher_init()
      |> Cipher.cipher_update(key)
      |> Cipher.cipher_final()

    %MlKemEnvp{}
    |> MlKemEnvp.set_cipher_context(recpCipherCtx)
    |> MlKemEnvp.set_cipher(cipher)
    |> MlKemEnvp.set_kdf_context(ContextConfig.get(kdf_output, :derivation_context))
    |> MlKemEnvp.set_recp_key_id(UniqueKeyIdGenerator.unique_key_id(recpKey))
    |> MlKemEnvp.set_recipient_cipher(recp_cipher)

    # with {:ok, curve_name} <- EccKeypair.oid_to_curve_name(curve),
    #     {:ok, %EccKeypair{private_key: epmPrivKey, public_key: epmPubKey}} =
    #       Asymkey.generate(%EccKeypair{curve: curve_name}) do
    #  shared_secret = :public_key.compute_key(recpPubKey, KeyEncoding.to_native!(epmPrivKey))

    #  kdf_output =
    #    ContextConfig.set(key_kc, :out_length, ContextConfig.get(key_cc, :key_byte_size))
    #    |> KDF.derive!(shared_secret)

    #  {:ok, %{cipher: cipher, cipher_context: recpCipherCtx, transient_key: _key}} =
    #    ContextConfig.set(key_cc, :session_key, ContextConfig.get(kdf_output, :derived_value))
    #    |> Cipher.cipher_init()
    #    |> Cipher.cipher_update(data)
    #    |> Cipher.cipher_final()

    #  %EciesEnvp{}
    #  |> EciesEnvp.set_cipher_context(recpCipherCtx)
    #  |> EciesEnvp.set_cipher(cipher)
    #  |> EciesEnvp.set_kdf_context(ContextConfig.get(kdf_output, :derivation_context))
    #  |> EciesEnvp.set_sender_public(epmPubKey)
    #  |> EciesEnvp.set_recp_key_id(
    #    UniqueKeyIdGenerator.unique_key_id(EccPublicKey.to_ecc_public_key(:native, recpKey))
    #  )
    # end
  end
end
