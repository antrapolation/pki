defmodule ExCcrypto.KDF.Bcrypt.BcryptEnvp do
  alias ExCcrypto.KDF.Bcrypt.BcryptEnvp
  use TypedStruct

  typedstruct do
    # Full bcrypt hash string e.g. "$2b$12$..."
    field(:derived_value, any())
    field(:derivation_context, any())
  end

  def get_derived_value(ctx), do: ctx.derived_value
  def set_derived_value(ctx, val), do: %BcryptEnvp{ctx | derived_value: val}

  def get_derivation_context(ctx), do: ctx.derivation_context
  def set_derivation_context(ctx, val), do: %BcryptEnvp{ctx | derivation_context: val}

  def equal?(%BcryptEnvp{} = envp, data) do
    Bcrypt.verify_pass(data, envp.derived_value)
  end
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.KDF.Bcrypt.BcryptEnvp do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.KDF.Bcrypt.BcryptEnvp

  def get(ctx, :derived_value, _default, _opts), do: BcryptEnvp.get_derived_value(ctx)
  def get(ctx, :derivation_context, _default, _opts), do: BcryptEnvp.get_derivation_context(ctx)

  def get(ctx, :equals?, data, _opts), do: BcryptEnvp.equal?(ctx, data)
  def get(ctx, :equal?, data, _opts), do: BcryptEnvp.equal?(ctx, data)

  def get(ctx, key, default, opts) do
    ContextConfig.get(BcryptEnvp.get_derivation_context(ctx), key, default, opts)
  end

  def set(_ctx, key, _value, _opts), do: {:error, {:unknown_setter_key, key}}

  def info(_ctx, :getter_key) do
    %{
      derived_value: "Return the full bcrypt hash string (e.g. \"$2b$12$...\")",
      derivation_context: "Return the derivation context that produced the output"
    }
  end

  def info(_ctx, :setter_key), do: %{}

  def info(_ctx, info),
    do: %{error: "Info operation error on BcryptEnvp. No info key '#{info}' found"}
end
