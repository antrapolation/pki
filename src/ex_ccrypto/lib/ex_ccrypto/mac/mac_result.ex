defmodule ExCcrypto.Mac.MacResult do
  alias ExCcrypto.Mac.MacResult
  use TypedStruct

  typedstruct do
    field(:mac_result, any())
    field(:mac_context, any())
  end

  def set_mac_result(%MacResult{} = ctx, val), do: %MacResult{ctx | mac_result: val}
  def get_mac_result(%MacResult{} = ctx), do: ctx.mac_result

  def set_mac_context(%MacResult{} = ctx, val), do: %MacResult{ctx | mac_context: val}
  def get_mac_context(%MacResult{} = ctx), do: ctx.mac_context
end
