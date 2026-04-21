defmodule ExCcrypto.Digest.DigestResult do
  alias ExCcrypto.Digest.DigestResult
  use TypedStruct

  typedstruct do
    field(:digested, any())
    field(:digest_context, any())
  end

  def set_digested_value(%DigestResult{} = ctx, val), do: %DigestResult{ctx | digested: val}
  def get_digested_value(%DigestResult{} = ctx), do: ctx.digested

  def set_digest_context(%DigestResult{} = ctx, val), do: %DigestResult{ctx | digest_context: val}
  def get_digest_context(%DigestResult{} = ctx), do: ctx.digest_context
end
