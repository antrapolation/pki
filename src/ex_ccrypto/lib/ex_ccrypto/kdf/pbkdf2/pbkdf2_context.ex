defmodule ExCcrypto.KDF.PBKDF2Context do
  alias ExCcrypto.KDF.PBKDF2Context
  use TypedStruct

  @type supported_hmac :: :sha | :sha224 | :sha256 | :sha384 | :sha512
  @type output_format :: :hex | :bin | :b64

  typedstruct do
    field(:hmac_algo, supported_hmac(), default: :sha256)
    field(:iterations, integer(), default: 100_000)
    field(:out_length, integer(), default: 32)
    field(:salt, binary())
    field(:salt_length, integer(), default: 16)
    field(:out_format, output_format(), default: :bin)
  end

  def set_hmac_algo(ctx, algo), do: %PBKDF2Context{ctx | hmac_algo: algo}
  def set_iterations(ctx, iterations), do: %PBKDF2Context{ctx | iterations: iterations}
  def set_out_length(ctx, len), do: %PBKDF2Context{ctx | out_length: len}

  def set_salt(ctx, salt) do
    case byte_size(salt) == ctx.salt_length do
      true ->
        %PBKDF2Context{ctx | salt: salt}

      false ->
        {:error, {:given_salt_does_not_match_required_length, byte_size(salt), ctx.salt_length}}
    end
  end

  def set_salt_length(ctx, len), do: %PBKDF2Context{ctx | salt_length: len}
  def set_out_format(ctx, of), do: %PBKDF2Context{ctx | out_format: of}

  def random_salt(ctx),
    do: %{ctx | salt: :crypto.strong_rand_bytes(ctx.salt_length)}

  def get_salt(%PBKDF2Context{} = ctx), do: ctx.salt
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.KDF.PBKDF2Context do
  alias ExCcrypto.KDF.PBKDF2Context

  def set(ctx, key, value, opts \\ nil)

  def set(ctx, :hmac_algo, value, _), do: PBKDF2Context.set_hmac_algo(ctx, value)
  def set(ctx, :iterations, value, _), do: PBKDF2Context.set_iterations(ctx, value)
  def set(ctx, :out_length, value, _), do: PBKDF2Context.set_out_length(ctx, value)

  def set(ctx, :salt, :random, _), do: PBKDF2Context.random_salt(ctx)
  def set(ctx, :salt, value, _), do: PBKDF2Context.set_salt(ctx, value)

  def set(ctx, :salt_length, value, _), do: PBKDF2Context.set_salt_length(ctx, value)
  def set(ctx, :out_format, value, _), do: PBKDF2Context.set_out_format(ctx, value)

  def get(ctx, key, default \\ nil, opts \\ nil)

  def get(ctx, :hmac_algo, def, _), do: get_value_or_default(ctx.hmac_algo, def)
  def get(ctx, :iterations, def, _), do: get_value_or_default(ctx.iterations, def)
  def get(ctx, :out_length, def, _), do: get_value_or_default(ctx.out_length, def)
  def get(ctx, :salt, def, _), do: get_value_or_default(ctx.salt, def)
  def get(ctx, :salt_length, def, _), do: get_value_or_default(ctx.salt_length, def)
  def get(ctx, :out_format, def, _), do: get_value_or_default(ctx.out_format, def)

  defp get_value_or_default(val, default) do
    cond do
      is_nil(val) or val == <<>> -> default
      true -> val
    end
  end

  def info(_ctx, :getter_key),
    do: %{
      hmac_algo: "Return HMAC algorithm atom",
      iterations: "Return iteration count",
      out_length: "Return output length in bytes",
      salt: "Return salt binary",
      salt_length: "Return salt length in bytes",
      out_format: "Return output format"
    }

  def info(_ctx, :setter_key),
    do: %{
      hmac_algo: "Set HMAC algorithm. Default :sha256. Options: :sha, :sha224, :sha256, :sha384, :sha512",
      iterations: "Set iteration count. Default 100_000",
      out_length: "Set output length in bytes. Default 32",
      salt: "Set salt binary or :random",
      salt_length: "Set salt length in bytes. Default 16",
      out_format: "Set output format. Default :bin. Options: :hex, :b64"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on PBKDF2Context. No info key '#{info}' found"}
end
