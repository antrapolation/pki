defmodule ExCcrypto.Cipher.CipherEngine.BlockCipherContext do
  alias ExCcrypto.Cipher.CipherEngine.BlockCipherContext
  alias ExCcrypto.Cipher.CipherEngine.CipherEnvp
  alias ExCcrypto.Utils.TempOut
  alias ExCcrypto.Utils.TempOut.MemoryTempOut
  use TypedStruct

  require Logger

  @type cipher_ops :: :encrypt | :decrypt
  typedstruct do
    field(:ops, cipher_ops(), default: :encrypt)
    field(:keysize, integer(), default: 256)
    field(:key_byte_size, integer(), default: 32)
    field(:mode, atom(), default: :ctr_mode)
    field(:iv_length, integer(), default: 16)
    field(:iv, binary())
    field(:external_iv, boolean(), default: false)
    field(:cipher_name, atom(), default: :aes_256_ctr)
    ## actual encryption key
    field(:transient_key, binary())
    field(:external_key, boolean(), default: false)
    field(:cipher_session, any())
    field(:temp_out, any(), default: TempOut.init(%MemoryTempOut{}))
    ## variant of the multiple modes
    field(:session_data, map(), default: %{})

    field(:cipher, binary())
    field(:attach_cipher, boolean(), default: false)
  end

  def encrypt_config() do
    %BlockCipherContext{ops: :encrypt}
  end

  def set_context_for_decryption(ctx, _opts \\ nil) do
    %BlockCipherContext{ctx | ops: :decrypt}
  end

  def set_context_for_encryption(ctx, _opts \\ nil) do
    %BlockCipherContext{ctx | ops: :encrypt}
  end

  def required_iv?(ctx) do
    ctx.iv_length > 0
  end

  def encryption_mode?(ctx) do
    ctx.ops == :encrypt
  end

  def set_cipher_session(ctx, session) do
    %BlockCipherContext{ctx | cipher_session: session}
  end

  def get_cipher_session(ctx), do: ctx.cipher_session

  def is_external_key?(ctx) do
    ctx.external_key
  end

  def set_keysize(conf, size) do
    %BlockCipherContext{conf | keysize: trunc(size * 8), key_byte_size: size}
  end

  def set_mode(conf, mode) do
    %BlockCipherContext{conf | mode: mode}
  end

  def set_iv(conf, iv) do
    cond do
      iv == :random ->
        %BlockCipherContext{
          conf
          | iv: :crypto.strong_rand_bytes(conf.iv_length),
            external_iv: false
        }

      is_nil(iv) ->
        {:error, :given_iv_is_nil}

      is_binary(iv) and byte_size(iv) == conf.iv_length ->
        %BlockCipherContext{conf | iv: iv, external_iv: true}

      is_binary(iv) and conf.iv_length > 0 and byte_size(iv) != conf.iv_length ->
        {:error, {:given_iv_does_not_meet_required_length, byte_size(iv), conf.iv_length}}

      true ->
        {:error, :given_iv_is_not_binary}
    end
  end

  def set_iv_length(conf, len) do
    %BlockCipherContext{conf | iv_length: len}
  end

  def generate_transient_key(conf) do
    %BlockCipherContext{
      conf
      | transient_key: :crypto.strong_rand_bytes(conf.key_byte_size),
        external_key: false
    }
  end

  # def generate_random_iv(%{mode: :gcm_mode} = conf),
  #  do: BlockCipherContext.set_iv(conf, {:random, 12})

  def generate_random_iv(conf), do: BlockCipherContext.set_iv(conf, :random)

  def set_transient_key(conf, key) do
    case byte_size(key) == conf.key_byte_size do
      true ->
        %BlockCipherContext{conf | transient_key: key, external_key: true}

      false ->
        {:error, {:required_key_length_not_match, byte_size(key), conf.key_byte_size}}
    end
  end

  def set_cipher_name(conf, name) do
    %BlockCipherContext{conf | cipher_name: name}
  end

  def set_temp_out(conf, out) do
    %BlockCipherContext{conf | temp_out: TempOut.init(out)}
  end

  def reset_temp_out(conf) do
    %BlockCipherContext{conf | temp_out: TempOut.init(%MemoryTempOut{})}
  end

  def attach_cipher(ctx, bool) when is_boolean(bool) do
    Logger.debug("attach_cipher value : #{inspect(bool)}")

    %BlockCipherContext{
      ctx
      | attach_cipher: bool
    }
  end

  def set_cipher_output(ctx, cipher),
    do: %BlockCipherContext{ctx | cipher: cipher, attach_cipher: true}

  def is_attach_cipher?(ctx), do: ctx.attach_cipher

  def set_user_key_kdf_context(conf, kdf_context) do
    set_session_data(conf, :user_key_kdf_context, kdf_context)
  end

  def get_user_key_kdf_context(conf), do: get_session_data(conf, :user_key_kdf_context)

  def set_session_data(ctx, key, value) do
    case Map.has_key?(ctx.session_data, key) do
      true ->
        %BlockCipherContext{ctx | session_data: %{ctx.session_data | key => value}}

      false ->
        %BlockCipherContext{ctx | session_data: Map.put_new(ctx.session_data, key, value)}
    end
  end

  def get_session_data(conf, key, default \\ nil) do
    case conf.session_data[key] do
      nil ->
        default

      res ->
        res
    end
  end

  def clear_session_data(conf, key, with_value \\ nil) do
    if has_session_data?(conf, key) do
      set_session_data(conf, key, with_value)
    end
  end

  def remove_session_data(conf, key) do
    case has_session_data?(conf, key) do
      true ->
        %BlockCipherContext{conf | session_data: Map.delete(conf.session_data, key)}

      false ->
        conf
    end
  end

  def has_session_data?(conf, key) do
    case conf.session_data[key] do
      nil -> false
      _ -> true
    end
  end

  def context_from_envp(envp) do
    ctx =
      %BlockCipherContext{
        %BlockCipherContext{}
        | keysize: envp.keysize,
          key_byte_size: envp.key_byte_size,
          mode: envp.mode,
          iv_length: envp.iv_length,
          cipher_name: envp.cipher_name,
          session_data: envp.session_data
      }

    # ctx =
    #  case CipherEnvp.has_transient_key?(envp) do
    #    true ->
    #      BlockCipherContext.set_transient_key(ctx, CipherEnvp.get_transient_key(envp))
    #      |> BlockCipherContext.remove_session_data(:transient_key)

    #    false ->
    #      ctx
    #  end

    ctx =
      case CipherEnvp.has_iv?(envp) do
        true -> ctx |> BlockCipherContext.set_iv(CipherEnvp.get_iv(envp))
        false -> ctx
      end

    case CipherEnvp.has_cipher?(envp) do
      true -> ctx |> BlockCipherContext.set_cipher_output(CipherEnvp.get_cipher(envp))
      false -> ctx
    end
  end
end

alias ExCcrypto.ContextConfig

defimpl ContextConfig, for: ExCcrypto.Cipher.CipherEngine.BlockCipherContext do
  alias ExCcrypto.Cipher.CipherEngine.BlockCipherContext

  def get(ctx, :key_byte_size, _, _), do: ctx.key_byte_size
  def get(ctx, :keysize, _, _), do: ctx.keysize
  def get(ctx, :iv, _, _), do: ctx.iv
  def get(ctx, :iv_length, _, _), do: ctx.iv_length
  def get(ctx, :mode, _, _), do: ctx.mode
  def get(ctx, :session_key, _, _), do: ctx.transient_key
  def get(ctx, :is_attach_cipher?, _, _), do: ctx.attach_cipher
  def get(ctx, :cipher_name, _, _), do: ctx.cipher_name

  def get(ctx, :user_key_kdf_context, _, _),
    do: BlockCipherContext.get_user_key_kdf_context(ctx)

  def get(_ctx, _key, default, _opts), do: default

  def set(ctx, key, value, opts \\ nil)

  def set(ctx, :session_key, :random, _), do: BlockCipherContext.generate_transient_key(ctx)
  def set(ctx, :session_key, value, _), do: BlockCipherContext.set_transient_key(ctx, value)

  def set(ctx, :iv, :random, _), do: BlockCipherContext.generate_random_iv(ctx)
  def set(ctx, :iv, value, _), do: BlockCipherContext.set_iv(ctx, value)

  def set(ctx, :user_key_kdf_context, value, _),
    do: BlockCipherContext.set_user_key_kdf_context(ctx, value)

  def set(ctx, key, value, _) when key in [:attached_cipher?, :cipher_attached?, :attach_cipher?],
    do: BlockCipherContext.attach_cipher(ctx, value)

  def set(ctx, :cipher_ops, :decrypt, _), do: BlockCipherContext.set_context_for_decryption(ctx)
  def set(ctx, :cipher_ops, :encrypt, _), do: BlockCipherContext.set_context_for_encryption(ctx)

  def set(_ctx, key, _value, _), do: {:error, {:setting_unknown_context_config_key, key}}

  def info(_ctx, :getter_key),
    do: %{
      key_byte_size: "Return key size in byte",
      keysize:
        "Return the keysize in natural unit. E.g for cipher it is usually in bits (128/256/384/512 bits)",
      iv: "Return the binary represening the IV value",
      iv_length: "Return the IV length in byte unit",
      mode: "Atom represeningthe cipher mode (:gcm/:cbc etc)",
      session_key: "Return the session key in binary",
      cipher_output: "Return the cipher output"
    }

  def info(_ctx, :setter_key),
    do: %{
      iv: "Set the IV of the operation",
      session_key: "Set the session key for the cipher operation",
      cipher_output: "Set the cipher output (attached cipher mode)"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on BlockCipherContext. No info key '#{info}' found"}
end
