defimpl ExCcrypto.Cipher, for: ExCcrypto.Cipher.CipherEngine.BlockCipherContext do
  alias ExCcrypto.Cipher.CipherEngine.CipherContextEncoder
  alias ExCcrypto.Cipher.CipherCommon
  alias ExCcrypto.Cipher.CipherEngine.BlockCipherContext
  alias ExCcrypto.Utils.TempOut

  require Logger

  def cipher_init(ctx, opts \\ nil)

  @doc """
  Mainly the encryption operation shall touch cipher_init here
  For decryption operation the cipher_init is handled by CipherEnvp
  """
  def cipher_init(%BlockCipherContext{transient_key: nil, ops: :encrypt} = ctx, opts) do
    cipher_init(BlockCipherContext.generate_transient_key(ctx), opts)
  end

  def cipher_init(%BlockCipherContext{iv: nil, iv_length: len, ops: :encrypt} = ctx, opts)
      when len > 0 do
    cipher_init(BlockCipherContext.generate_random_iv(ctx), opts)
  end

  def cipher_init(%BlockCipherContext{ops: :decrypt, transient_key: nil}, _opts),
    do: {:error, :decryption_key_is_required}

  def cipher_init(%BlockCipherContext{ops: :decrypt, iv: nil, iv_length: len}, _opts)
      when len > 0,
      do: {:error, :decryption_iv_is_required}

  def cipher_init(ctx, _opts) do
    csess =
      case BlockCipherContext.required_iv?(ctx) do
        false ->
          Logger.debug("Cipher without iv : #{ctx.cipher_name}")

          :crypto.crypto_init(
            ctx.cipher_name,
            ctx.transient_key,
            # BlockCipherContext.encryption_mode?(ctx)
            [{:encrypt, BlockCipherContext.encryption_mode?(ctx)}, {:padding, :pkcs_padding}]
          )

        true ->
          Logger.debug("Cipher with iv : #{ctx.cipher_name}")

          :crypto.crypto_init(
            ctx.cipher_name,
            ctx.transient_key,
            ctx.iv,
            [{:encrypt, BlockCipherContext.encryption_mode?(ctx)}, {:padding, :pkcs_padding}]
          )
      end

    BlockCipherContext.set_cipher_session(ctx, csess)
  end

  def cipher_update(ctx, data \\ nil)

  def cipher_update(%BlockCipherContext{ops: :encrypt}, data)
      when is_nil(data) or byte_size(data) == 0,
      do: {:error, :data_is_required}

  def cipher_update(%BlockCipherContext{ops: :encrypt} = ctx, data) do
    res = :crypto.crypto_update(BlockCipherContext.get_cipher_session(ctx), data)
    %BlockCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, res)}
  end

  def cipher_update(%BlockCipherContext{ops: :decrypt, attach_cipher: false} = ctx, data) do
    res = :crypto.crypto_update(BlockCipherContext.get_cipher_session(ctx), data)
    %BlockCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, res)}
  end

  def cipher_update(%BlockCipherContext{ops: :decrypt, attach_cipher: true} = ctx, _data) do
    res = :crypto.crypto_update(BlockCipherContext.get_cipher_session(ctx), ctx.cipher)
    %BlockCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, res)}
  end

  def cipher_final(%BlockCipherContext{transient_key: tkey, ops: ops}, _opts)
      when is_nil(tkey) or byte_size(tkey) == 0 do
    case ops do
      :encrypt ->
        {:error, :encryption_key_not_available}

      :decrypt ->
        {:error, :decryption_key_not_available}
    end
  end

  def cipher_final(%BlockCipherContext{ops: :encrypt} = ctx, _opts) do
    res = :crypto.crypto_final(BlockCipherContext.get_cipher_session(ctx))
    # IO.puts("enc final : #{inspect(res)}")
    ctx = %BlockCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, res)}

    cond do
      ctx.attach_cipher == false ->
        {:ok,
         %{
           cipher: TempOut.final(ctx.temp_out),
           cipher_context: encode_context(ctx),
           transient_key: ctx.transient_key
         }}

      ctx.attach_cipher == true ->
        {:ok,
         %{
           cipher_context:
             encode_context(
               ctx
               |> BlockCipherContext.set_cipher_output(TempOut.final(ctx.temp_out))
             ),
           transient_key: ctx.transient_key
         }}

      true ->
        {:ok,
         %{
           cipher: TempOut.final(ctx.temp_out),
           cipher_context: encode_context(ctx),
           transient_key: ctx.transient_key
         }}
    end
  end

  def cipher_final(%BlockCipherContext{ops: :decrypt} = ctx, _opts) do
    res = :crypto.crypto_final(BlockCipherContext.get_cipher_session(ctx))
    # IO.puts("dec final : #{inspect(res)}")
    ctx = %BlockCipherContext{ctx | temp_out: TempOut.update(ctx.temp_out, res)}

    {:ok, TempOut.final(ctx.temp_out)}
  end

  defp encode_context(%{external_iv: true, attach_cipher: true} = ctx) do
    Logger.debug("Encode public info with cipher")
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
    Logger.debug("Encode with iv and cipher detached")
    CipherContextEncoder.encode!(ctx, :with_iv_without_cipher)
  end

  defdelegate cipher(ctx, data, opts), to: CipherCommon
end
