# tag 0x08
defmodule StrapCiphagile.Context.Signature do
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
    field(:format, any(), default: :raw)
    # TLV 0x01
    field(:signature, any())
    # optional
    # TLV 0x02
    field(:plaintext, any())
    # optional
    # TLV 0x03
    field(:digest, any())
    # TLV 0x04 - Hash Algorithm (one byte)
    field(:hash_algo, any())
    # TLV 0xF0
    field(:misc, any())
  end

  def new(algo, variant, hash_algo \\ nil) do
    %__MODULE__{
      version: :v1_0,
      algo: algo,
      variant: variant,
      hash_algo: hash_algo
    }
  end
end

alias StrapCiphagile.EncoderProtocol
alias StrapCiphagile.DecoderProtocol
alias StrapCiphagile.VarLengthData
alias StrapCiphagile.Context.Signature
alias StrapCiphagile.Context.Asymkey.Encodings
alias StrapCiphagile.Tags

defimpl EncoderProtocol, for: Signature do
  def encode(%Signature{} = ctx, _opts) do
    with {:ok, version_byte} <- Encodings.encode_version(ctx.version),
         {:ok, algo_byte} <- Encodings.encode_algo(ctx.algo),
         {:ok, variant_byte} <- Encodings.encode_variant(ctx.algo, ctx.variant),
         {:ok, format_byte} <- Encodings.encode_signature_format(ctx.format),
         {:ok, signature_bin} <- Encodings.encode_tlv(0x01, ctx.signature),
         {:ok, pt_bin} <- Encodings.encode_tlv(0x02, ctx.plaintext),
         {:ok, digest_bin} <- encode_digest_tlv(ctx.digest),
         {:ok, hash_algo_bin} <- encode_hash_algo_tlv(ctx.hash_algo),
         {:ok, misc_bin} <- Encodings.encode_tlv(0xF0, ctx.misc) do
      content =
        <<version_byte, algo_byte, variant_byte, format_byte>> <>
          signature_bin <> pt_bin <> digest_bin <> hash_algo_bin <> misc_bin

      with {:ok, full_data} <- VarLengthData.encode(content),
           {:ok, tag} <- Tags.tag_value(:signature_envp) do
        {:ok, <<tag>> <> full_data}
      else
        err -> err
      end
    else
      err -> err
    end
  end

  defp encode_digest_tlv(nil), do: {:ok, <<>>}

  defp encode_digest_tlv(digest_struct) do
    # Encode the inner Hashing struct which produces <<0x01, data_length, ...>>
    case EncoderProtocol.encode(digest_struct) do
      {:ok, inner_bin} ->
        # Strip the outer 0x01 magic byte tag that Hashing produced and wrap the inner data into TLV 0x03
        case inner_bin do
          <<0x01, hashing_data::binary>> ->
            with {:ok, final_encoded} <- VarLengthData.encode(hashing_data) do
              {:ok, <<0x03>> <> final_encoded}
            end

          _ ->
            {:error, :invalid_digest_encoding_format}
        end

      err ->
        err
    end
  end

  # Hash Algorithm encoding (one byte) - TLV 0x04
  defp encode_hash_algo_tlv(nil), do: {:ok, <<>>}

  defp encode_hash_algo_tlv(hash_algo) do
    with {:ok, algo_byte} <- encode_hash_algo(hash_algo) do
      {:ok, <<0x04, algo_byte>>}
    end
  end

  defp encode_hash_algo(:sha2), do: {:ok, 0x01}
  defp encode_hash_algo(:sha3), do: {:ok, 0x02}
  defp encode_hash_algo(:photon), do: {:ok, 0x03}
  defp encode_hash_algo(:spongent), do: {:ok, 0x04}
  defp encode_hash_algo(:ripemd), do: {:ok, 0x05}
  defp encode_hash_algo(:sm3), do: {:ok, 0x06}
  defp encode_hash_algo(:acson), do: {:ok, 0x07}
  defp encode_hash_algo(_), do: {:error, :unsupported_hash_algo}
end

defimpl DecoderProtocol, for: Signature do
  def decode(%Signature{} = _ctx, bin, _opts) do
    with true <- match?(<<0x08, _::binary>>, bin),
         <<_tag_byte, rest_after_tag::binary>> <- bin,
         {:ok, content, outer_rest} <- VarLengthData.decode(rest_after_tag),
         <<version_byte, algo_byte, variant_byte, format_byte, inner_rest::binary>> <- content,
         {:ok, version} <- Encodings.decode_version(version_byte),
         {:ok, algo} <- Encodings.decode_algo(algo_byte),
         {:ok, variant} <- Encodings.decode_variant(algo, variant_byte),
         {:ok, format} <- Encodings.decode_signature_format(format_byte),
         {:ok, sig_struct} <-
           decode_tlv(inner_rest, %Signature{
             version: version,
             algo: algo,
             variant: variant,
             format: format
           }) do
      if outer_rest == "" do
        {:ok, sig_struct}
      else
        {:ok, {sig_struct, outer_rest}}
      end
    else
      false -> {:error, :incorrect_tag}
      _ -> {:error, :decoding_failed}
    end
  end

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | signature: val})
    end
  end

  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | plaintext: val})
    end
  end

  defp decode_tlv(<<0x03, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      # reconstruct the inner Hashing binary block by prepending the 0x01 Hashing context tag
      inner_block = <<0x01>> <> val

      case DecoderProtocol.decode(%StrapCiphagile.Context.Hashing{}, inner_block) do
        {:ok, hash_struct} -> decode_tlv(rest_after, %{acc | digest: hash_struct})
        {:ok, {hash_struct, _}} -> decode_tlv(rest_after, %{acc | digest: hash_struct})
        err -> err
      end
    end
  end

  defp decode_tlv(<<0x04, algo_byte, rest::binary>>, acc) do
    with {:ok, hash_algo} <- decode_hash_algo(algo_byte) do
      decode_tlv(rest, %{acc | hash_algo: hash_algo})
    end
  end

  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | misc: val})
    end
  end

  defp decode_tlv(_, _), do: {:error, :invalid_tlv}

  defp decode_hash_algo(0x01), do: {:ok, :sha2}
  defp decode_hash_algo(0x02), do: {:ok, :sha3}
  defp decode_hash_algo(0x03), do: {:ok, :photon}
  defp decode_hash_algo(0x04), do: {:ok, :spongent}
  defp decode_hash_algo(0x05), do: {:ok, :ripemd}
  defp decode_hash_algo(0x06), do: {:ok, :sm3}
  defp decode_hash_algo(0x07), do: {:ok, :acson}
  defp decode_hash_algo(_), do: {:error, :unknown_hash_algo}
end
