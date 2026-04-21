defmodule ExCcrypto.Cipher.CipherCommon do
  alias ExCcrypto.Cipher

  def cipher(ctx, data, opts) do
    Cipher.cipher_init(ctx, opts)
    |> Cipher.cipher_update(data)
    |> Cipher.cipher_final(opts)
  end
end
