defmodule ExCcrypto.Asymkey.AsymkeyHelper do
  alias ExCcrypto.Asymkey.AsymkeyVerify

  def verify(ctx, data, signature, opts) do
    AsymkeyVerify.verify_init(ctx, opts)
    |> AsymkeyVerify.verify_update(data)
    |> AsymkeyVerify.verify_final(signature)
  end
end
