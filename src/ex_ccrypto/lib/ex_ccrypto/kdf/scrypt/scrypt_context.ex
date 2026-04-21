defmodule ExCcrypto.KDF.ScryptContext do
  alias ExCcrypto.KDF.ScryptContext
  use TypedStruct

  @type output_format :: :hex | :bin | :b64

  typedstruct do
    # CPU/memory cost parameter, must be a power of 2
    field(:n, integer(), default: 16384)
    # block size
    field(:r, integer(), default: 8)
    # parallelization factor
    field(:p, integer(), default: 1)
    field(:out_length, integer(), default: 32)
    field(:salt, binary())
    field(:salt_length, integer(), default: 16)
    field(:out_format, output_format(), default: :bin)
  end

  def set_n(ctx, n), do: %ScryptContext{ctx | n: n}
  def set_r(ctx, r), do: %ScryptContext{ctx | r: r}
  def set_p(ctx, p), do: %ScryptContext{ctx | p: p}
  def set_out_length(ctx, len), do: %ScryptContext{ctx | out_length: len}

  def set_salt(ctx, salt) do
    case byte_size(salt) == ctx.salt_length do
      true ->
        %ScryptContext{ctx | salt: salt}

      false ->
        {:error, {:given_salt_does_not_match_required_length, byte_size(salt), ctx.salt_length}}
    end
  end

  def set_salt_length(ctx, len), do: %ScryptContext{ctx | salt_length: len}
  def set_out_format(ctx, of), do: %ScryptContext{ctx | out_format: of}

  def random_salt(ctx),
    do: %{ctx | salt: :crypto.strong_rand_bytes(ctx.salt_length)}

  def get_salt(%ScryptContext{} = ctx), do: ctx.salt
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.KDF.ScryptContext do
  alias ExCcrypto.KDF.ScryptContext

  def set(ctx, key, value, opts \\ nil)

  def set(ctx, :n, value, _), do: ScryptContext.set_n(ctx, value)
  def set(ctx, :r, value, _), do: ScryptContext.set_r(ctx, value)
  def set(ctx, :p, value, _), do: ScryptContext.set_p(ctx, value)
  def set(ctx, :out_length, value, _), do: ScryptContext.set_out_length(ctx, value)

  def set(ctx, :salt, :random, _), do: ScryptContext.random_salt(ctx)
  def set(ctx, :salt, value, _), do: ScryptContext.set_salt(ctx, value)

  def set(ctx, :salt_length, value, _), do: ScryptContext.set_salt_length(ctx, value)
  def set(ctx, :out_format, value, _), do: ScryptContext.set_out_format(ctx, value)

  def get(ctx, key, default \\ nil, opts \\ nil)

  def get(ctx, :n, def, _), do: get_value_or_default(ctx.n, def)
  def get(ctx, :r, def, _), do: get_value_or_default(ctx.r, def)
  def get(ctx, :p, def, _), do: get_value_or_default(ctx.p, def)
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
      n: "Return CPU/memory cost parameter N",
      r: "Return block size parameter r",
      p: "Return parallelization factor p",
      out_length: "Return output length in bytes",
      salt: "Return salt binary",
      salt_length: "Return salt length in bytes",
      out_format: "Return output format"
    }

  def info(_ctx, :setter_key),
    do: %{
      n: "Set CPU/memory cost N (must be power of 2). Default 16384",
      r: "Set block size r. Default 8",
      p: "Set parallelization factor p. Default 1",
      out_length: "Set output length in bytes. Default 32",
      salt: "Set salt binary or :random",
      salt_length: "Set salt length in bytes. Default 16",
      out_format: "Set output format. Default :bin. Options: :hex, :b64"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on ScryptContext. No info key '#{info}' found"}
end
