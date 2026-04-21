defmodule ExCcrypto.KDF.Scrypt.ScryptEnvp do
  alias ExCcrypto.KDF
  alias ExCcrypto.KDF.KDFContextBuilder
  alias ExCcrypto.KDF.Scrypt.ScryptEnvp
  use TypedStruct

  typedstruct do
    field(:derived_value, any())
    field(:derivation_context, any())
  end

  def get_derived_value(ctx), do: ctx.derived_value
  def set_derived_value(ctx, val), do: %ScryptEnvp{ctx | derived_value: val}

  def get_derivation_context(ctx), do: ctx.derivation_context
  def set_derivation_context(ctx, val), do: %ScryptEnvp{ctx | derivation_context: val}

  def equal?(%ScryptEnvp{} = envp, data) do
    {:ok, gen} =
      KDFContextBuilder.kdf_context(envp.derivation_context)
      |> KDF.derive(data)

    envp.derived_value == gen.derived_value
  end
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.KDF.Scrypt.ScryptEnvp do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.KDF.Scrypt.ScryptEnvp

  def get(ctx, :derived_value, _default, _opts), do: ScryptEnvp.get_derived_value(ctx)
  def get(ctx, :derivation_context, _default, _opts), do: ScryptEnvp.get_derivation_context(ctx)

  def get(ctx, :equals?, data, _opts), do: ScryptEnvp.equal?(ctx, data)
  def get(ctx, :equal?, data, _opts), do: ScryptEnvp.equal?(ctx, data)

  def get(ctx, key, default, opts) do
    ContextConfig.get(ScryptEnvp.get_derivation_context(ctx), key, default, opts)
  end

  def set(_ctx, key, _value, _opts), do: {:error, {:unknown_setter_key, key}}

  def info(_ctx, :getter_key) do
    %{
      derived_value: "Return the derived value / output",
      derivation_context: "Return the derivation context that produced the output"
    }
  end

  def info(_ctx, :setter_key), do: %{}

  def info(_ctx, info),
    do: %{error: "Info operation error on ScryptEnvp. No info key '#{info}' found"}
end
