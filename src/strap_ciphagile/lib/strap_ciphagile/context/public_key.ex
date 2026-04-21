# tag 0x11
defmodule StrapCiphagile.Context.PublicKey do
  use TypedStruct

  typedstruct do
    field(:version, any(), default: :v1_0)
    # Master Algos:
    # KAZ-SIGN : 0x01
    # ML-DSA   : 0x02
    # SLH-DSA  : 0x03
    # Falcon   : 0x04
    # KAZ-KEM  : 0x10
    # ML-KEM   : 0x11
    # KAZ-KA   : 0x20
    # RSA      : 0x40
    # ECC      : 0x41
    field(:algo, any())
    field(:variant, any())
    field(:format, any(), default: :der)
    field(:key_value, any())
    # TLV 0xF0
    field(:misc, any())
  end

  def new(algo, variant \\ -1) do
    %__MODULE__{
      version: :v1_0,
      algo: algo,
      variant: variant
    }
  end
end

alias StrapCiphagile.EncoderProtocol
alias StrapCiphagile.DecoderProtocol
alias StrapCiphagile.VarLengthData
alias StrapCiphagile.Context.PublicKey
alias StrapCiphagile.Context.Asymkey.Encodings
alias StrapCiphagile.Tags

defimpl EncoderProtocol, for: PublicKey do
  def encode(%PublicKey{} = ctx, _opts) do
    with {:ok, version_byte} <- Encodings.encode_version(ctx.version),
         {:ok, algo_byte} <- Encodings.encode_algo(ctx.algo),
         {:ok, variant_byte} <- Encodings.encode_variant(ctx.algo, ctx.variant),
         {:ok, format_byte} <- Encodings.encode_asymkey_format(ctx.format),
         {:ok, pub_key_bin} <- Encodings.encode_tlv(0x01, ctx.key_value),
         {:ok, misc_bin} <- Encodings.encode_tlv(0xF0, ctx.misc) do
      content = <<version_byte, algo_byte, variant_byte, format_byte>> <> pub_key_bin <> misc_bin

      with {:ok, full_data} <- VarLengthData.encode(content),
           {:ok, tag} <- Tags.tag_value(:pubkey_envp) do
        {:ok, <<tag>> <> full_data}
      else
        err -> err
      end
    else
      err -> err
    end
  end
end

defimpl DecoderProtocol, for: PublicKey do
  def decode(%PublicKey{} = _ctx, bin, _opts) do
    with true <- match?(<<0x11, _::binary>>, bin),
         <<_tag_byte, rest_after_tag::binary>> <- bin,
         {:ok, content, outer_rest} <- VarLengthData.decode(rest_after_tag),
         <<version_byte, algo_byte, variant_byte, format_byte, inner_rest::binary>> <- content,
         {:ok, version} <- Encodings.decode_version(version_byte),
         {:ok, algo} <- Encodings.decode_algo(algo_byte),
         {:ok, variant} <- Encodings.decode_variant(algo, variant_byte),
         {:ok, format} <- Encodings.decode_asymkey_format(format_byte),
         {:ok, pubkey_struct} <-
           decode_tlv(inner_rest, %PublicKey{
             version: version,
             algo: algo,
             variant: variant,
             format: format
           }) do
      if outer_rest == "" do
        {:ok, pubkey_struct}
      else
        {:ok, {pubkey_struct, outer_rest}}
      end
    else
      false -> {:error, :incorrect_tag}
      _ -> {:error, :decoding_failed}
    end
  end

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | key_value: val})
    end
  end

  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | misc: val})
    end
  end

  defp decode_tlv(_, _), do: {:error, :invalid_tlv}
end
