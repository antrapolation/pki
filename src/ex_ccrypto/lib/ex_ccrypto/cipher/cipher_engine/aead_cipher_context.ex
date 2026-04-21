defmodule ExCcrypto.Cipher.CipherEngine.AeadCipherContext do
  alias ExCcrypto.Cipher.CipherEngine.AeadCipherContext
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
    field(:mode, atom(), default: :gcm)
    field(:iv_length, integer(), default: 12)
    field(:iv, binary())
    field(:external_iv, boolean(), default: false)
    field(:cipher_name, atom(), default: :aes_256_gcm)
    ## actual encryption key
    field(:transient_key, binary())
    field(:external_key, boolean(), default: false)
    field(:temp_out, any(), default: TempOut.init(%MemoryTempOut{}))
    field(:aad, any(), default: "")
    ## variant of the multiple modes
    field(:session_data, map(), default: %{})

    field(:cipher, binary())
    field(:attach_cipher, boolean(), default: false)
  end

  def encrypt_config() do
    %AeadCipherContext{ops: :encrypt}
  end

  def set_context_for_decryption(ctx, _opts \\ nil) do
    %AeadCipherContext{ctx | ops: :decrypt}
  end

  def set_context_for_encryption(ctx, _opts \\ nil) do
    %AeadCipherContext{ctx | ops: :encrypt}
  end

  # def set_keysize(conf, size) do
  #  %AeadCipherContext{conf | keysize: trunc(size * 8), key_byte_size: size}
  # end

  # def set_mode(conf, mode) do
  #  %AeadCipherContext{conf | mode: mode}
  # end

  def set_aad(ctx, aad) do
    %AeadCipherContext{ctx | aad: aad}
  end

  def set_iv(conf, iv) do
    cond do
      iv == :random ->
        %AeadCipherContext{
          conf
          | iv: :crypto.strong_rand_bytes(conf.iv_length),
            external_iv: false
        }

      is_nil(iv) ->
        {:error, :given_iv_is_nil}

      is_binary(iv) and byte_size(iv) == conf.iv_length ->
        %AeadCipherContext{conf | iv: iv, external_iv: true}

      is_binary(iv) ->
        {:error, {:given_iv_does_not_meet_required_length, byte_size(iv), conf.iv_length}}

      true ->
        {:error, :given_iv_is_not_binary}
    end
  end

  # def set_iv_length(conf, len) do
  #  %AeadCipherContext{conf | iv_length: len}
  # end

  def generate_transient_key(conf) do
    %AeadCipherContext{
      conf
      | transient_key: :crypto.strong_rand_bytes(conf.key_byte_size),
        external_key: false
    }
  end

  def generate_random_iv(conf), do: AeadCipherContext.set_iv(conf, :random)

  def get_iv(%AeadCipherContext{} = conf), do: conf.iv

  def set_transient_key(conf, key) do
    case byte_size(key) == conf.key_byte_size do
      true ->
        %AeadCipherContext{conf | transient_key: key, external_key: true}

      false ->
        {:error, {:required_key_length_not_match, byte_size(key), conf.key_byte_size}}
    end
  end

  # def set_cipher_name(conf, name) do
  #  %AeadCipherContext{conf | cipher_name: name}
  # end

  def set_temp_out(conf, out) do
    %AeadCipherContext{conf | temp_out: TempOut.init(out)}
  end

  def reset_temp_out(conf) do
    %AeadCipherContext{conf | temp_out: TempOut.init(%MemoryTempOut{})}
  end

  def set_tag(ctx, tag) do
    set_session_data(ctx, :tag, tag)
  end

  def get_tag(ctx) do
    get_session_data(ctx, :tag, <<>>)
  end

  def attach_cipher(ctx, bool) when is_boolean(bool),
    do: %AeadCipherContext{
      ctx
      | attach_cipher: bool
    }

  def set_cipher_output(ctx, cipher),
    do: %AeadCipherContext{ctx | cipher: cipher, attach_cipher: true}

  def is_attach_cipher?(ctx), do: ctx.attach_cipher

  def set_user_key_kdf_context(conf, kdf_context) do
    set_session_data(conf, :user_key_kdf_context, kdf_context)
  end

  def get_user_key_kdf_context(conf), do: get_session_data(conf, :user_key_kdf_context)

  defp set_session_data(conf, key, value) do
    case has_session_data?(conf, key) do
      true ->
        %AeadCipherContext{conf | session_data: %{conf.session_data | key => value}}

      false ->
        %AeadCipherContext{conf | session_data: Map.put_new(conf.session_data, key, value)}
    end
  end

  defp get_session_data(conf, key, default \\ nil) do
    case conf.session_data[key] do
      nil ->
        default

      res ->
        res
    end
  end

  def remove_session_data(conf, key) do
    case has_session_data?(conf, key) do
      true ->
        %AeadCipherContext{conf | session_data: Map.delete(conf.session_data, key)}

      false ->
        conf
    end
  end

  defp has_session_data?(conf, key) do
    case conf.session_data[key] do
      nil -> false
      _ -> true
    end
  end

  def context_from_envp(%CipherEnvp{} = envp) do
    ctx =
      %AeadCipherContext{
        %AeadCipherContext{}
        | keysize: envp.keysize,
          key_byte_size: envp.key_byte_size,
          mode: envp.mode,
          iv_length: envp.iv_length,
          cipher_name: envp.cipher_name,
          session_data: envp.session_data
      }

    ctx =
      case CipherEnvp.has_iv?(envp) do
        true -> ctx |> AeadCipherContext.set_iv(CipherEnvp.get_iv(envp))
        false -> ctx
      end

    case CipherEnvp.has_cipher?(envp) do
      true -> ctx |> AeadCipherContext.set_cipher_output(CipherEnvp.get_cipher(envp))
      false -> ctx
    end
  end
end

alias ExCcrypto.ContextConfig

defimpl ContextConfig, for: ExCcrypto.Cipher.CipherEngine.AeadCipherContext do
  alias ExCcrypto.Cipher.CipherEngine.AeadCipherContext

  def get(ctx, :key_byte_size, def, _), do: get_value_or_default(ctx.key_byte_size, def)
  def get(ctx, :keysize, def, _), do: get_value_or_default(ctx.keysize, def)
  def get(ctx, :iv, def, _), do: get_value_or_default(ctx.iv, def)
  def get(ctx, :iv_length, def, _), do: get_value_or_default(ctx.iv_length, def)
  def get(ctx, :mode, def, _), do: get_value_or_default(ctx.mode, def)
  def get(ctx, :session_key, def, _), do: get_value_or_default(ctx.transient_key, def)
  def get(ctx, :is_attach_cipher?, def, _), do: get_value_or_default(ctx.attach_cipher, def)
  def get(ctx, :cipher_name, def, _), do: get_value_or_default(ctx.cipher_name, def)

  def get(ctx, :tag, def, _), do: get_value_or_default(AeadCipherContext.get_tag(ctx), def)

  def get(ctx, :user_key_kdf_context, def, _),
    do: get_value_or_default(AeadCipherContext.get_user_key_kdf_context(ctx), def)

  def get(_ctx, _key, default, _opts), do: default

  defp get_value_or_default(val, default) do
    case val do
      nil -> default
      res -> res
    end
  end

  def set(ctx, key, value, opts \\ nil)

  def set(ctx, :session_key, :random, _), do: AeadCipherContext.generate_transient_key(ctx)
  def set(ctx, :session_key, value, _), do: AeadCipherContext.set_transient_key(ctx, value)

  def set(ctx, :aad, value, _),
    do: %AeadCipherContext{ctx | aad: value}

  def set(ctx, :iv, :random, _), do: AeadCipherContext.generate_random_iv(ctx)
  def set(ctx, :iv, value, _), do: AeadCipherContext.set_iv(ctx, value)

  def set(ctx, :user_key_kdf_context, value, _),
    do: AeadCipherContext.set_user_key_kdf_context(ctx, value)

  def set(ctx, key, value, _) when key in [:attached_cipher?, :cipher_attached?, :attach_cipher?],
    do: AeadCipherContext.attach_cipher(ctx, value)

  def set(ctx, :cipher_ops, :decrypt, _), do: AeadCipherContext.set_context_for_decryption(ctx)
  def set(ctx, :cipher_ops, :encrypt, _), do: AeadCipherContext.set_context_for_encryption(ctx)

  def set(ctx, :tag, value, _), do: AeadCipherContext.set_tag(ctx, value)

  def set(ctx, _key, _value, _), do: ctx

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
      aad:
        "Set the Additional Authenticated Data (AAD) of a GCM operation. Has no effect on non AEAD cipher",
      cipher_output: "Set the cipher output (attached cipher mode)"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on AeadCipherContext. No info key '#{info}' found"}
end
