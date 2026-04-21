defmodule ExCcrypto.KDF.BcryptContext do
  alias ExCcrypto.KDF.BcryptContext
  use TypedStruct

  # Bcrypt salt is always 16 bytes before encoding
  @bcrypt_salt_length 16

  typedstruct do
    field(:rounds, integer(), default: 12)
    # 16-byte raw binary salt
    field(:salt, binary())
    field(:salt_length, integer(), default: @bcrypt_salt_length)
  end

  def set_rounds(ctx, rounds), do: %BcryptContext{ctx | rounds: rounds}

  def set_salt(ctx, salt) do
    case byte_size(salt) == @bcrypt_salt_length do
      true ->
        %BcryptContext{ctx | salt: salt}

      false ->
        {:error, {:bcrypt_salt_must_be_16_bytes, byte_size(salt)}}
    end
  end

  def random_salt(ctx),
    do: %{ctx | salt: :crypto.strong_rand_bytes(@bcrypt_salt_length)}

  def get_salt(%BcryptContext{} = ctx), do: ctx.salt
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.KDF.BcryptContext do
  alias ExCcrypto.KDF.BcryptContext

  def set(ctx, key, value, opts \\ nil)

  def set(ctx, :rounds, value, _), do: BcryptContext.set_rounds(ctx, value)

  def set(ctx, :salt, :random, _), do: BcryptContext.random_salt(ctx)
  def set(ctx, :salt, value, _), do: BcryptContext.set_salt(ctx, value)

  def get(ctx, key, default \\ nil, opts \\ nil)

  def get(ctx, :rounds, def, _), do: get_value_or_default(ctx.rounds, def)
  def get(ctx, :salt, def, _), do: get_value_or_default(ctx.salt, def)
  def get(ctx, :salt_length, _def, _), do: ctx.salt_length

  defp get_value_or_default(val, default) do
    cond do
      is_nil(val) or val == <<>> -> default
      true -> val
    end
  end

  def info(_ctx, :getter_key),
    do: %{
      rounds: "Return bcrypt cost factor (log rounds)",
      salt: "Return 16-byte raw salt binary",
      salt_length: "Return salt length in bytes (always 16)"
    }

  def info(_ctx, :setter_key),
    do: %{
      rounds: "Set bcrypt cost factor. Default 12. Valid range: 4–31",
      salt: "Set 16-byte raw salt binary or :random"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on BcryptContext. No info key '#{info}' found"}
end
