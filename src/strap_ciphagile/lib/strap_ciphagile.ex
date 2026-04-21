defmodule StrapCiphagile do
  alias StrapCiphagile.Tags
  alias StrapCiphagile.DecoderProtocol
  alias StrapCiphagile.Context.Hashing
  alias StrapCiphagile.EncoderProtocol

  @version_to_byte %{v1_0: 0x01, v2_0: 0x02}

  def encode(ctx, opts \\ %{}) do
    with {:ok, bin} <- EncoderProtocol.encode(ctx, opts),
         {:ok, magic} <- Tags.tag_value(:magic),
         {:ok, version_byte} <- encode_version(ctx.version) do
      {:ok, magic <> <<version_byte>> <> bin}
    end
  end

  defp encode_version(:v1_0), do: {:ok, 0x01}
  defp encode_version(:v2_0), do: {:ok, 0x02}

  defp encode_version(version) when is_atom(version),
    do: {:error, {:unsupported_version, version}}

  defp encode_version(version), do: {:error, {:invalid_version, version}}

  def decode(<<0xAF, 0x08, 0x01, rest::binary>>), do: do_decode(rest)
  def decode(_), do: {:error, :invalid_format_or_magic_tag}

  defp do_decode(<<0x01, _rest::binary>> = bin), do: DecoderProtocol.decode(%Hashing{}, bin)

  defp do_decode(<<0x02, _rest::binary>> = bin),
    do: DecoderProtocol.decode(%StrapCiphagile.Context.KDF{}, bin)

  defp do_decode(<<0x10, _rest::binary>> = bin),
    do: DecoderProtocol.decode(%StrapCiphagile.Context.Symkey{}, bin)

  defp do_decode(<<0x0A, _rest::binary>> = bin),
    do: DecoderProtocol.decode(%StrapCiphagile.Context.SymkeyCipher{}, bin)

  defp do_decode(<<0x08, _rest::binary>> = bin),
    do: DecoderProtocol.decode(%StrapCiphagile.Context.Signature{}, bin)

  defp do_decode(<<0x11, _rest::binary>> = bin),
    do: DecoderProtocol.decode(%StrapCiphagile.Context.PublicKey{}, bin)

  defp do_decode(<<0x12, _rest::binary>> = bin),
    do: DecoderProtocol.decode(%StrapCiphagile.Context.PrivateKey{}, bin)
end
