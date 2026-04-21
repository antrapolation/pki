defimpl ExCcrypto.Cipher, for: Any do
  alias ExCcrypto.Cipher
  def cipher_init(ctx, _opts), do: prompt_error(ctx, :cipher_init)
  def cipher_update(ctx, _data), do: prompt_error(ctx, :cipher_update)
  def cipher_final(ctx, _opts), do: prompt_error(ctx, :cipher_final)

  def cipher(ctx, data, opts) do
    Cipher.cipher_init(ctx, opts)
    |> Cipher.cipher_update(data)
    |> Cipher.cipher_final(opts)
  end

  defp prompt_error(ctx, _opts) when is_tuple(ctx), do: ctx

  defp prompt_error(ctx, ops) do
    %mod{} = ctx.__struct__
    {:error, {String.to_atom("#{ops}_not_implemented"), mod}}
  end
end
