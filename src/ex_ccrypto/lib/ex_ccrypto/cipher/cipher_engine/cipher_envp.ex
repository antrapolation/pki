defmodule ExCcrypto.Cipher.CipherEngine.CipherEnvp do
  alias ExCcrypto.Cipher.CipherEngine.AeadCipherContext
  alias ExCcrypto.Cipher.CipherEngine.BlockCipherContext
  alias ExCcrypto.Cipher.CipherEngine.CipherEnvp

  @moduledoc """
  Representing cipher output
  """

  use TypedStruct

  typedstruct do
    field(:keysize, integer(), default: 256)
    field(:key_byte_size, integer(), default: 32)
    field(:mode, atom(), default: :gcm)
    field(:iv_length, integer(), default: 12)
    field(:cipher_name, atom(), default: :aes_256_gcm)
    field(:aead, boolean())
    ## variant of the multiple modes
    field(:session_data, map(), default: %{})
  end

  def envp_from_context(%AeadCipherContext{} = ctx) do
    %CipherEnvp{
      %CipherEnvp{}
      | keysize: ctx.keysize,
        key_byte_size: ctx.key_byte_size,
        mode: ctx.mode,
        iv_length: ctx.iv_length,
        cipher_name: ctx.cipher_name,
        # this key required for decode
        aead: true,
        session_data: ctx.session_data
    }
  end

  def envp_from_context(%BlockCipherContext{} = ctx) do
    %CipherEnvp{
      %CipherEnvp{}
      | keysize: ctx.keysize,
        key_byte_size: ctx.key_byte_size,
        mode: ctx.mode,
        iv_length: ctx.iv_length,
        cipher_name: ctx.cipher_name,
        # this key required for decode
        aead: false,
        session_data: ctx.session_data
    }
  end

  def set_iv(%CipherEnvp{} = cipher, iv) do
    %CipherEnvp{cipher | session_data: Map.put_new(cipher.session_data, :iv, iv)}
  end

  def has_iv?(%CipherEnvp{} = cipher) do
    case cipher.session_data[:iv] do
      nil -> false
      _ -> true
    end
  end

  def get_iv(%CipherEnvp{} = cipher) do
    cipher.session_data[:iv]
  end

  def get_tag(%CipherEnvp{} = cipher) do
    cipher.session_data[:tag]
  end

  def set_cipher(envp, cipher) do
    %CipherEnvp{envp | session_data: Map.put_new(envp.session_data, :cipher, cipher)}
  end

  def get_cipher(envp), do: envp.session_data[:cipher]

  def has_cipher?(envp) do
    c = CipherEnvp.get_cipher(envp)

    cond do
      is_nil(c) == true -> false
      byte_size(c) == 0 -> false
      true -> true
    end
  end
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Cipher.CipherEngine.CipherEnvp do
  alias ExCcrypto.Cipher.CipherEngine.CipherEnvp

  # def set(ctx, :session_key, value, _opts), do: CipherEnvp.set_transient_key(ctx, value)
  def set(ctx, _, _, _), do: ctx

  def get(ctx, :key_byte_size, _, _), do: ctx.key_byte_size
  def get(ctx, :keysize, _, _), do: ctx.keysize
  def get(ctx, :iv_length, _, _), do: ctx.iv_length
  def get(ctx, :mode, _, _), do: ctx.mode

  # def get(ctx, :session_key, _, _) do
  #  CipherEnvp.get_transient_key(ctx)
  # end

  def get(ctx, :iv, _, _), do: CipherEnvp.get_iv(ctx)
  def get(ctx, :tag, _, _), do: CipherEnvp.get_tag(ctx)

  def get(ctx, :user_key_kdf_context, def, _) do
    case ctx.session_data do
      %{user_key_kdf_context: val} -> val
      _ -> def
    end
  end

  def get(_ctx, key, _default, _opts), do: {:error, {:no_such_field, key}}

  def info(_ctx, :getter_key),
    do: %{
      key_byte_size: "Return key size in byte",
      keysize:
        "Return the keysize in natural unit. E.g for cipher it is usually in bits (128/256/384/512 bits)",
      iv: "Return the binary represening the IV value",
      iv_length: "Return the IV length in byte unit",
      mode: "Atom represeningthe cipher mode (:gcm/:cbc etc)",
      session_key: "Return the session key in binary"
    }

  def info(_ctx, :setter_key),
    do: %{
      session_key: "Set the session key for the cipher operation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on CipherEnvp. No info key '#{info}' found"}
end

# This would be decrypt operation
defimpl ExCcrypto.Cipher, for: ExCcrypto.Cipher.CipherEngine.CipherEnvp do
  alias ExCcrypto.KDF
  alias ExCcrypto.Cipher
  alias ExCcrypto.Cipher.CipherCommon
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Cipher.CipherEngine.BlockCipherContext
  alias ExCcrypto.Cipher.CipherEngine.AeadCipherContext
  alias ExCcrypto.Cipher.CipherEngine.CipherEnvp

  require Logger

  # shall only be called on decrypt operation since CipherEnvp
  # is the output of encryption
  def cipher_init(ctx, opts \\ nil)

  def cipher_init(%CipherEnvp{aead: true} = ctx, opts) do
    opts = opts || %{}
    ctx =
      AeadCipherContext.context_from_envp(ctx)
      |> AeadCipherContext.set_context_for_decryption()

    # with {:ok, ctx} <- set_session_key(ctx, opts[:session_key]),
    with {:ok, ctx} <- set_session_key(ctx, opts),
         {:ok, ctx} <- set_iv(ctx, opts[:iv]) do
      Cipher.cipher_init(ctx, opts)
    end
  end

  def cipher_init(%CipherEnvp{aead: false} = ctx, opts) do
    opts = opts || %{}
    Logger.debug("block cipher envp : #{inspect(ctx)}")

    ctx =
      BlockCipherContext.context_from_envp(ctx)
      |> BlockCipherContext.set_context_for_decryption()

    # with {:ok, ctx} <- set_session_key(ctx, opts[:session_key]),
    with {:ok, ctx} <- set_session_key(ctx, opts),
         {:ok, ctx} <- set_iv(ctx, opts[:iv]) do
      Cipher.cipher_init(ctx)
    end
  end

  defp set_session_key(ctx, opts) do
    key = opts[:session_key]
    pass = opts[:password]

    ctx =
      cond do
        is_nil(key) or byte_size(key) == 0 ->
          cond do
            is_nil(pass) or byte_size(pass) == 0 ->
              {:ok, ctx}

            ContextConfig.get(ctx, :user_key_kdf_context) == nil ->
              {:ok, ctx}

            true ->
              derived =
                ContextConfig.get(ctx, :user_key_kdf_context)
                |> KDF.derive!(pass)

              {:ok,
               ContextConfig.set(ctx, :session_key, ContextConfig.get(derived, :derived_value))}
          end

        byte_size(key) > 0 and byte_size(key) == ctx.key_byte_size ->
          {:ok, ContextConfig.set(ctx, :session_key, key)}

        byte_size(key) > 0 and byte_size(key) != ctx.key_byte_size ->
          {:error, {:wrong_session_key_length, byte_size(key), ctx.key_byte_size}}
      end

    with {:ok, ctx} <- ctx do
      cond do
        is_nil(ContextConfig.get(ctx, :session_key)) or
            byte_size(ContextConfig.get(ctx, :session_key)) == 0 ->
          {:error, :decryption_key_is_required}

        true ->
          {:ok, ctx}
      end
    end
  end

  defp set_iv(ctx, iv) do
    ctx =
      cond do
        is_nil(iv) ->
          {:ok, ctx}

        byte_size(iv) == 0 ->
          {:ok, ctx}

        byte_size(iv) == ctx.iv_length ->
          {:ok, ContextConfig.set(ctx, :iv, iv)}

        byte_size(iv) != ctx.iv_length ->
          {:error, {:wrong_iv_length, byte_size(iv), ctx.iv_length}}
      end

    with {:ok, ctx} <- ctx do
      cond do
        ctx.iv_length > 0 and (is_nil(ctx.iv) or byte_size(ctx.iv) == 0) ->
          {:error, :decryption_iv_is_required}

        true ->
          {:ok, ctx}
      end
    end
  end

  # by protocol operation guideline, after cipher_init
  # returned AeadCipherContext/BlockCipherContext,
  # protocol implemented by
  # AeadCipherContext/BlockCipherContext shall take over
  def cipher_update(ctx, _data), do: ctx

  def cipher_final(ctx, _opts), do: ctx

  defdelegate cipher(ctx, data, opts), to: CipherCommon
end
