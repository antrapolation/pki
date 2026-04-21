defimpl ExCcrypto.Cipher, for: ExCcrypto.Cipher.CipherEngine.AeadCipherContext do
  alias ExCcrypto.Cipher.CipherEngine.CipherContextEncoder
  alias ExCcrypto.Cipher.CipherCommon
  alias ExCcrypto.Cipher.CipherEngine.AeadCipherContext
  alias ExCcrypto.Utils.TempOut

  require Logger

  def cipher_init(ctx, opts \\ nil)

  def cipher_init(%AeadCipherContext{ops: :encrypt, transient_key: nil} = ctx, opts) do
    cipher_init(AeadCipherContext.generate_transient_key(ctx), opts)
  end

  def cipher_init(%AeadCipherContext{ops: :encrypt, iv: nil} = ctx, opts) do
    cipher_init(AeadCipherContext.generate_random_iv(ctx), opts)
  end

  # def cipher_init(%AeadCipherContext{ops: :decrypt, transient_key: nil} = ctx, opts) do
  #  # Logger.debug("cipher_init opts : #{inspect(opts)}")

  #  case opts[:password] do
  #    nil ->
  #      {:error, :decryption_key_is_required}

  #    pass ->
  #      case AeadCipherContext.get_user_key_kdf_context(ctx) do
  #        nil ->
  #          {:error, :user_password_is_required}

  #        kdf ->
  #          derived =
  #            ContextConfig.set(kdf, :out_length, ContextConfig.get(ctx, :key_byte_size))
  #            |> KDF.derive!(pass)

  #          AeadCipherContext.set_transient_key(ctx, ContextConfig.get(derived, :derived_value))
  #      end
  #  end
  # end

  # do: {:error, :decryption_key_is_required}

  # def cipher_init(%AeadCipherContext{ops: :decrypt, iv: nil, iv_length: len}, _opts)
  #    when len > 0,
  #    do: {:error, :decryption_iv_is_required}

  def cipher_init(ctx, opts) when is_map(opts) do
    # Logger.debug("opts in cipher_init : #{inspect(opts)}")

    case opts[:aad] do
      nil ->
        AeadCipherContext.set_aad(ctx, "")

      aad when byte_size(aad) > 0 ->
        AeadCipherContext.set_aad(ctx, aad)
    end
  end

  def cipher_init(ctx, _opts) do
    # Logger.debug("opts in cipher_init fall back: #{inspect(opts)}")
    ctx
  end

  def cipher_update(ctx, data \\ nil)

  def cipher_update(%AeadCipherContext{ops: :encrypt}, data)
      when is_nil(data) or byte_size(data) == 0,
      do: {:error, :data_is_required}

  def cipher_update(%AeadCipherContext{ops: :encrypt} = ctx, data) do
    %AeadCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, data)}
  end

  def cipher_update(%AeadCipherContext{ops: :decrypt, attach_cipher: false} = ctx, data) do
    %AeadCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, data)}
  end

  def cipher_update(%AeadCipherContext{ops: :decrypt, attach_cipher: true} = ctx, _data) do
    %AeadCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, ctx.cipher)}
  end

  def cipher_final(%AeadCipherContext{transient_key: tkey, ops: ops}, _opts)
      when is_nil(tkey) or byte_size(tkey) == 0 do
    case ops do
      :encrypt ->
        {:error, :encryption_key_not_available}

      :decrypt ->
        {:error, :decryption_key_not_available}
    end
  end

  def cipher_final(%AeadCipherContext{ops: :encrypt} = ctx, _opts) do
    {cipher, ctx} = encrypt(ctx)

    # transient_key always returned to allow 
    # 1. Construction of shared and recovery cipher
    # 2. Internal generated session key
    cond do
      ctx.attach_cipher == false ->
        {:ok,
         %{cipher: cipher, cipher_context: encode_context(ctx), transient_key: ctx.transient_key}}

      ctx.attach_cipher == true ->
        {:ok,
         %{
           cipher_context: encode_context(ctx |> AeadCipherContext.set_cipher_output(cipher)),
           transient_key: ctx.transient_key
         }}

      true ->
        {:ok,
         %{cipher: cipher, cipher_context: encode_context(ctx), transient_key: ctx.transient_key}}
    end
  end

  def cipher_final(%AeadCipherContext{ops: :decrypt} = ctx, _opts) do
    case decrypt(ctx) do
      :error -> {:error, :decryption_failed}
      res -> {:ok, res}
    end
  end

  defp encrypt(ctx) do
    {cipher, tag} =
      :crypto.crypto_one_time_aead(
        ctx.cipher_name,
        ctx.transient_key,
        ctx.iv,
        TempOut.final(ctx.temp_out),
        ctx.aad,
        16,
        true
      )

    # {cipher, reset_encrypt_session(ctx) |> AeadCipherContext.set_tag(tag)}
    {cipher, AeadCipherContext.set_tag(ctx, tag)}
  end

  # defp reset_encrypt_session(ctx) do
  #  AeadCipherContext.reset_temp_out(ctx)
  # end

  defp decrypt(ctx) do
    tag =
      case AeadCipherContext.get_tag(ctx) do
        nil -> <<>>
        res -> res
      end

    Logger.debug("cipher decrypt ctx : #{inspect(ctx)}")

    :crypto.crypto_one_time_aead(
      ctx.cipher_name,
      ctx.transient_key,
      ctx.iv,
      TempOut.final(ctx.temp_out),
      ctx.aad,
      tag,
      false
    )
  end

  defp encode_context(%{external_iv: true, attach_cipher: true} = ctx) do
    Logger.debug("Encode public info  with cipher attached")

    CipherContextEncoder.encode!(ctx, :public_info_with_cipher)
  end

  defp encode_context(%{external_iv: true, attach_cipher: false} = ctx) do
    Logger.debug("Encode public info with cipher detached")

    CipherContextEncoder.encode!(ctx, :public_info_without_cipher)
  end

  defp encode_context(%{external_iv: false, attach_cipher: true} = ctx) do
    Logger.debug("Encode with iv and cipher attached")

    CipherContextEncoder.encode!(ctx, :with_iv_and_cipher)
  end

  defp encode_context(%{external_iv: false, attach_cipher: false} = ctx) do
    Logger.debug("Encode with iv with cipher detached")

    CipherContextEncoder.encode!(ctx, :with_iv_without_cipher)
  end

  defdelegate cipher(ctx, data, opts), to: CipherCommon
end
