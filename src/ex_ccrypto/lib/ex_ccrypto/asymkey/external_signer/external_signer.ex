# Public Struct
defmodule ExCcrypto.Asymkey.ExternalSigner do
  @moduledoc """
  This structure is the map to the structure understood 
  by the underlying X509 library
  This structure is more to construct of PKCS encoded output
  of the digital signature field
  """
  alias ExCcrypto.Asymkey.ExternalSigner

  use TypedStruct

  typedstruct do
    field(:callback, function())
    field(:key_algo, atom())
    field(:public_key, any())
  end

  def set_callback(ctx, func) do
    %ExternalSigner{ctx | callback: func}
  end

  def set_key_algo(ctx, kalgo) do
    %ExternalSigner{ctx | key_algo: kalgo}
  end

  def set_public_key(ctx, pubkey) do
    %ExternalSigner{ctx | public_key: pubkey}
  end
end

defimpl ExCcrypto.Asymkey.KeyEncoding, for: ExCcrypto.Asymkey.ExternalSigner do
  def to_native(key, _opts),
    do: {:ok, %{callback: key.callback, key_algo: key.key_algo, public_key: key.public_key}}

  def to_native!(key, opts) do
    {:ok, val} = to_native(key, opts)
    val
  end

  def encode(key, _format, _opts),
    do: {:ok, %{callback: key.callback, key_algo: key.key_algo, public_key: key.public_key}}

  def encode!(key, format, opts) do
    {:ok, val} = encode(key, format, opts)
    val
  end
end
