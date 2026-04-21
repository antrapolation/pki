defmodule ExCcrypto.Mac.MacContext do
  alias ExCcrypto.Mac.MacContext
  use TypedStruct

  typedstruct do
    field(:type, atom())
    field(:variant, atom(), default: nil)
    field(:key, binary())
    field(:key_byte_size, integer(), default: 0)
    field(:mac_session, any())
  end

  def set_type(ctx, type), do: %MacContext{ctx | type: type}
  def set_type(ctx, type, variant), do: %MacContext{ctx | type: type, variant: variant}
  def set_key(ctx, key), do: %MacContext{ctx | key: key}
  def set_key_byte_size(ctx, keysize), do: %MacContext{ctx | key_byte_size: keysize}
  def get_key_byte_size(ctx), do: ctx.key_byte_size

  def set_session(ctx, session), do: %MacContext{ctx | mac_session: session}
  def get_session(ctx), do: ctx.mac_session

  def generate_key(ctx) do
    case ctx.key_byte_size do
      0 -> {:error, :key_size_not_given}
      res -> MacContext.set_key(ctx, :crypto.strong_rand_bytes(res))
    end
  end

  def get_key(ctx), do: ctx.key
  def clear_key(ctx), do: MacContext.set_key(ctx, nil)

  def get_and_clear_key(ctx) do
    key = MacContext.get_key(ctx)
    ctx = MacContext.clear_key(ctx)
    {key, ctx}
  end
end

defimpl ExCcrypto.Mac, for: ExCcrypto.Mac.MacContext do
  alias ExCcrypto.Mac.MacResult
  alias ExCcrypto.Mac
  alias ExCcrypto.Mac.MacContext

  require Logger

  def mac_init(ctx, opts \\ nil)

  def mac_init(%{key: nil} = ctx, opts), do: mac_init(MacContext.generate_key(ctx), opts)

  def mac_init(%{variant: nil} = ctx, _opts) do
    MacContext.set_session(ctx, :crypto.mac_init(ctx.type, ctx.key))
  end

  def mac_init(ctx, _opts) do
    MacContext.set_session(ctx, :crypto.mac_init(ctx.type, ctx.variant, ctx.key))
  end

  def mac_update(ctx, data) do
    :crypto.mac_update(ctx.mac_session, data)
    ctx
  end

  @spec mac_final(MacContext.t()) :: {:ok, map()}
  def mac_final(ctx) do
    val = :crypto.mac_final(ctx.mac_session)
    ctx = MacContext.set_session(ctx, nil)
    # {:ok, %{mac: val, context: ctx}}

    {:ok,
     %MacResult{
       mac_context: ctx,
       mac_result: val
     }}
  end

  def mac(ctx, data, opts) do
    Mac.mac_init(ctx, opts)
    |> Mac.mac_update(data)
    |> Mac.mac_final()
  end

  def mac_match?(ctx, data, mac, opts) do
    with {:ok, %{mac: res}} <- mac(ctx, data, opts) do
      res == mac
    end
  end
end

defimpl ExCcrypto.ContextConfig, for: ExCcrypto.Mac.MacContext do
  alias ExCcrypto.Mac.MacContext

  def set(ctx, :key, value, _opts), do: MacContext.set_key(ctx, value)
  def set(_ctx, key, _value, _opts), do: {:error, {:setting_key_not_supported, key}}

  def get(ctx, :key, _def, _opts), do: MacContext.get_key(ctx)
  def get(ctx, :key_byte_size, _def, _opts), do: MacContext.get_key_byte_size(ctx)
  def get(ctx, :get_and_clear_key, _def, _opts), do: MacContext.get_and_clear_key(ctx)
  def get(_ctx, key, _default, _opts), do: {:error, {:unknown_key, key}}

  def info(_ctx, :getter_key),
    do: %{}

  def info(_ctx, :setter_key),
    do: %{
      key: "Set the key in binary for this MAC operation"
    }

  def info(_ctx, info),
    do: %{error: "Info operation error on MacContext. No info key '#{info}' found"}
end
