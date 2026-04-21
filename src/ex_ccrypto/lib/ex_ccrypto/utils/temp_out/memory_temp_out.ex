defmodule ExCcrypto.Utils.TempOut.MemoryTempOut do
  use TypedStruct

  typedstruct do
    field(:session, list(), default: [])
  end
end

alias ExCcrypto.Utils.TempOut

defimpl TempOut, for: ExCcrypto.Utils.TempOut.MemoryTempOut do
  alias ExCcrypto.Utils.TempOut.MemoryTempOut

  def init(ctx, _opts), do: ctx

  def update(ctx, data) do
    %MemoryTempOut{ctx | session: [data | ctx.session]}
  end

  def final(ctx) do
    Enum.join(Enum.reverse(ctx.session))
  end
end
