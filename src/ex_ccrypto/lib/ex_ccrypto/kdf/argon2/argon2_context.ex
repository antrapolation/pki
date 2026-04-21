defmodule ExCcrypto.KDF.Argon2Context do
  alias ExCcrypto.KDF.Argon2Context
  use TypedStruct

  @type supported_variant :: :argon2i | :argon2d | :argon2id
  @type output_format :: :hex | :bin | :b64
  typedstruct do
    field(:variant, supported_variant(), default: :argon2id)
    field(:time_cost, integer(), default: 4)
    field(:memory_cost, integer(), default: 16)
    field(:parallel, integer(), default: 4)
    field(:out_length, integer(), default: 32)
    field(:salt, binary())
    field(:salt_length, integer(), default: 16)
    field(:out_format, Argon2.output_format(), default: :bin)
  end

  def set_variant(ctx, variant), do: %Argon2Context{ctx | variant: variant}
  def set_time_cost(ctx, tc), do: %Argon2Context{ctx | time_cost: tc}
  def set_memory_cost(ctx, mc), do: %Argon2Context{ctx | memory_cost: mc}
  def set_parallel(ctx, parallel), do: %Argon2Context{ctx | parallel: parallel}
  def set_out_length(ctx, len), do: %Argon2Context{ctx | out_length: len}

  def set_salt(ctx, salt) do
    case byte_size(salt) == ctx.salt_length do
      true ->
        %Argon2Context{ctx | salt: salt}

      false ->
        {:error, {:given_salt_does_not_match_required_length, byte_size(salt), ctx.salt_length}}
    end
  end

  def set_salt_length(ctx, len), do: %Argon2Context{ctx | salt_length: len}
  def set_out_format(ctx, of), do: %Argon2Context{ctx | out_format: of}

  def random_salt(ctx),
    do: %{ctx | salt: :crypto.strong_rand_bytes(ctx.salt_length)}

  def get_salt(%Argon2Context{} = ctx), do: ctx.salt

  def normalize(ctx) do
    min_memory = 8
    default_memory = 16

    memory_cost =
      case ctx.memory_cost do
        val when is_integer(val) and val >= min_memory -> val
        _ -> default_memory
      end

    %Argon2Context{ctx | memory_cost: memory_cost}
  end
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.KDF.Argon2Context do
  alias ExCcrypto.KDF.Argon2Context

  require Logger
  def set(ctx, key, value, opts \\ nil)

  def set(ctx, :time_cost, value, _), do: Argon2Context.set_time_cost(ctx, value)
  def set(ctx, :memory_cost, value, _), do: Argon2Context.set_memory_cost(ctx, value)
  def set(ctx, :parallel, value, _), do: Argon2Context.set_parallel(ctx, value)
  def set(ctx, :out_length, value, _), do: Argon2Context.set_out_length(ctx, value)

  def set(ctx, :salt, :random, _), do: Argon2Context.random_salt(ctx)
  def set(ctx, :salt, value, _), do: Argon2Context.set_salt(ctx, value)

  def set(ctx, :salt_length, value, _), do: Argon2Context.set_salt_length(ctx, value)
  def set(ctx, :out_format, value, _), do: Argon2Context.set_out_format(ctx, value)

  def get(ctx, key, default \\ nil, opts \\ nil)

  def get(ctx, :variant, def, _), do: get_value_or_default(ctx.variant, def)
  def get(ctx, :time_cost, def, _), do: get_value_or_default(ctx.time_cost, def)
  def get(ctx, :memory_cost, def, _), do: get_value_or_default(ctx.memory_cost, def)
  def get(ctx, :parallel, def, _), do: get_value_or_default(ctx.parallel, def)
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
      variant: "Return Argon2 variant name",
      time_cost: "Return current time cost value",
      memory_cost: "Return current memory cost value",
      parallel: "Return current parallel value",
      out_length: "Return current output length value in byte unit",
      salt: "Return current salt value in binary",
      salt_length: "Return current salt length value in byte unit",
      out_format: "Return current output format"
    }

  def info(_ctx, :setter_key),
    do: %{
      time_cost: "set time cost value in integer",
      memory_cost: "Set memory cost value in integer",
      parallel: "Set current parallel value in integer",
      out_length: "Set current output length value in byte unit",
      salt: "Set current salt value in binary",
      salt_length: "Set current salt length value in byte unit",
      out_format: "Set output format. Default is :bin, Other options including: :hex, :b64"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on Argon2Context. No info key '#{info}' found"}
end
