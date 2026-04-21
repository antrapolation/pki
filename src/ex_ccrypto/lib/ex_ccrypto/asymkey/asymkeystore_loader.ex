# Public API
defmodule ExCcrypto.Asymkey.AsymkeystoreLoader do
  alias ExCcrypto.Cipher

  def from_keystore(ks, opts) when is_binary(ks) do
    with {:ok, decoded} <- safe_binary_to_term(ks) do
      from_keystore(decoded, opts)
    end
  end

  def from_keystore(%{cipher_context: ctx, cipher: c}, %{password: pass})
      when not is_nil(pass) and byte_size(pass) > 0 do
    with {:ok, plain} <-
           Cipher.cipher_init(ctx, %{password: pass})
           |> Cipher.cipher_update(c)
           |> Cipher.cipher_final() do
      safe_binary_to_term(plain)
    else
      {:error, :decryption_failed} -> {:error, :password_incorrect}
      err -> err
    end
  end

  def from_keystore(_ks, _opts), do: {:error, :invalid_keystore_format}

  defp safe_binary_to_term(binary) do
    try do
      {:ok, :erlang.binary_to_term(binary, [:safe])}
    rescue
      ArgumentError -> {:error, :invalid_keystore_format}
    end
  end
end
