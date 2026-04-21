# Public API
defprotocol ExCcrypto.Asymkey.KeyEncoding do
  @spec to_native(map(), map()) :: {:ok, binary()} | {:error, any()}
  def to_native(key, opts \\ nil)

  @spec to_native!(any(), any()) :: binary() | no_return()
  def to_native!(key, opts \\ nil)

  @spec encode(map(), atom(), map()) :: {:ok, binary()} | {:error, any()}
  def encode(key, format, opts \\ nil)

  @spec encode(map(), atom(), map()) :: binary() | no_return()
  def encode!(key, format, opts \\ nil)
end

defmodule ExCcrypto.Asymkey.KeyEncodingException do
  defexception message: :key_encoding_exception
end
