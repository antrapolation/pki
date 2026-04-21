defmodule ExCcrypto.Cipher.Encoder.SimpleCipherModEncoder do
  alias ExCcrypto.Cipher.Encoder.SimpleCipherModEncoder
  alias ExCcrypto.Cipher.CipherModEncoder

  # extension points
  # Possible encoding: ASN.1 for external system to parse or generate
  @behaviour CipherModEncoder

  def encode(ctx, to_format \\ :bin, opts \\ nil)

  def encode(ctx, :bin, _opts), do: {:ok, :erlang.term_to_binary(ctx)}

  def encode(_ctx, format, _opts), do: {:error, {:unsupported_encoding_to_format, format}}

  def encode!(ctx, to_format \\ :bin, opts \\ nil) do
    with {:ok, res} <- SimpleCipherModEncoder.encode(ctx, to_format, opts) do
      res
    end
  end

  def decode(input, to_format \\ :native, _opts \\ nil)

  def decode(input, :native, _opts) do
    try do
      {:ok, :erlang.binary_to_term(input, [:safe])}
    rescue
      ArgumentError -> {:error, :invalid_encoding}
    end
  end

  def decode(_input, to_format, _opts), do: {:error, {:unsupported_decoding_to_format, to_format}}

  def decode!(input, to_format \\ :native, opts \\ nil) do
    with {:ok, res} <- SimpleCipherModEncoder.decode(input, to_format, opts) do
      res
    end
  end
end
