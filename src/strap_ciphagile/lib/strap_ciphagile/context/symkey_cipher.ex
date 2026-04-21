defmodule StrapCiphagile.Context.SymkeyCipher do
  use TypedStruct

  # SymkeyCipher tag is 0x09
  typedstruct do
    field(:version, any(), default: :v1_0)

    # CBC : 0x01
    # GCM : 0x02
    # XTS : 0x03
    field(:mode, any())

    # TLV of full Symkey structure
    # tag 0x01
    # Mandatory field
    field(:symkey, any())

    # TLV
    # tag 0x10
    # Optional
    field(:iv, any())

    # TLV
    # tag 0x11
    # Optional
    field(:aad, any())

    # TLV
    # tag 0x12
    # Optional
    field(:tag, any())

    # TLV
    # tag 0x03
    # Optional
    field(:cipher, any())

    # TLV 0xF0
    field(:misc, any())
  end
end

alias StrapCiphagile.Context.SymkeyCipher
alias StrapCiphagile.Context.Symkey
alias StrapCiphagile.EncoderProtocol
alias StrapCiphagile.DecoderProtocol
alias StrapCiphagile.VarLengthData

defimpl EncoderProtocol, for: SymkeyCipher do
  alias StrapCiphagile.Tags

  def encode(%SymkeyCipher{} = ctx, _opts) do
    with :ok <- validate_iv_length(ctx.symkey, ctx.mode, ctx.iv),
         {:ok, version_byte} <- encode_version(ctx.version),
         {:ok, mode_byte} <- encode_mode(ctx.mode),
         {:ok, symkey_bin} <- encode_tlv(0x01, ctx.symkey),
         {:ok, iv_bin} <- encode_tlv(0x10, ctx.iv),
         {:ok, cipher_bin} <- encode_tlv(0x03, ctx.cipher),
         {:ok, aad_bin} <- encode_tlv(0x11, ctx.aad),
         {:ok, tag_bin} <- encode_tlv(0x12, ctx.tag),
         {:ok, misc_bin} <- encode_tlv(0xF0, ctx.misc) do
      content =
        <<version_byte, mode_byte>> <>
          symkey_bin <> iv_bin <> cipher_bin <> aad_bin <> tag_bin <> misc_bin

      with {:ok, full_data} <- VarLengthData.encode(content),
           {:ok, tag} <- Tags.tag_value(:symkey_cipher_envp) do
        {:ok, <<tag>> <> full_data}
      else
        err -> err
      end
    else
      err -> err
    end
  end

  def expected_min_iv_length(_, :cbc), do: 16
  def expected_min_iv_length(_, :gcm), do: 12
  def expected_min_iv_length(_, :xts), do: 16
  def expected_min_iv_length(:chacha20, _), do: 12
  def expected_min_iv_length(_, _), do: 0

  defp validate_iv_length(_, _, nil), do: :ok
  defp validate_iv_length(nil, _, _), do: :ok

  defp validate_iv_length(%StrapCiphagile.Context.Symkey{algo: algo, variant: variant}, mode, iv) do
    min_len = expected_min_iv_length(algo, mode)

    if byte_size(iv) >= min_len do
      :ok
    else
      {:error, {:invalid_iv_size, algo, variant, mode, byte_size(iv)}}
    end
  end

  defp encode_version(:v1_0), do: {:ok, 0x01}
  defp encode_version(_), do: {:error, :unsupported_version}

  defp encode_mode(:cbc), do: {:ok, 0x01}
  defp encode_mode(:gcm), do: {:ok, 0x02}
  defp encode_mode(:xts), do: {:ok, 0x03}
  defp encode_mode(_), do: {:error, :unknown_mode}

  defp encode_tlv(0x01, nil), do: {:error, :missing_mandatory_field}
  defp encode_tlv(_tag, nil), do: {:ok, <<>>}

  # Symkey struct
  defp encode_tlv(0x01, %Symkey{} = val) do
    with {:ok, encoded} <- EncoderProtocol.encode(val),
         {:ok, len_val} <- VarLengthData.encode(encoded) do
      {:ok, <<0x01>> <> len_val}
    end
  end

  # Binary fields (iv, cipher, aad, tag)
  defp encode_tlv(tag, val) when is_binary(val) do
    with {:ok, len_val} <- VarLengthData.encode(val) do
      {:ok, <<tag>> <> len_val}
    end
  end

  defp encode_tlv(tag, _), do: {:error, {:invalid_field_type, "0x#{Integer.to_string(tag, 16)}"}}
end

defimpl DecoderProtocol, for: SymkeyCipher do
  def decode(%SymkeyCipher{} = _ctx, bin, _opts) do
    with <<0x0A, rest_after_tag::binary>> <- bin,
         {:ok, content, outer_rest} <- VarLengthData.decode(rest_after_tag),
         <<version_byte, mode_byte, inner_rest::binary>> <- content,
         {:ok, version} <- decode_version(version_byte),
         {:ok, mode} <- decode_mode(mode_byte),
         {:ok, final_struct} <-
           decode_tlv(inner_rest, %SymkeyCipher{version: version, mode: mode}) do
      if outer_rest == "" do
        {:ok, final_struct}
      else
        {:ok, {final_struct, outer_rest}}
      end
    else
      err -> {:error, {:decoding_failed, err, bin}}
    end
  end

  defp decode_version(0x01), do: {:ok, :v1_0}
  defp decode_version(_), do: {:error, :unknown_version}

  defp decode_mode(0x01), do: {:ok, :cbc}
  defp decode_mode(0x02), do: {:ok, :gcm}
  defp decode_mode(0x03), do: {:ok, :xts}
  defp decode_mode(_), do: {:error, :unknown_mode}

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  # Symkey (0x01)
  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    with {:ok, val_bin, rest_after} <- VarLengthData.decode(rest),
         {:ok, symkey_struct} <- DecoderProtocol.decode(%Symkey{}, val_bin) do
      decode_tlv(rest_after, %{acc | symkey: symkey_struct})
    end
  end

  # IV (0x02)
  defp decode_tlv(<<0x10, rest::binary>>, acc) do
    with {:ok, val_bin, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | iv: val_bin})
    end
  end

  # Cipher (0x03)
  defp decode_tlv(<<0x03, rest::binary>>, acc) do
    with {:ok, val_bin, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | cipher: val_bin})
    end
  end

  # AAD (0x10)
  defp decode_tlv(<<0x11, rest::binary>>, acc) do
    with {:ok, val_bin, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | aad: val_bin})
    end
  end

  # Tag (0x11 - mapped internal docs say tag 0x12)
  defp decode_tlv(<<0x12, rest::binary>>, acc) do
    with {:ok, val_bin, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | tag: val_bin})
    end
  end

  # Misc (0xF0)
  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    with {:ok, val_bin, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | misc: val_bin})
    end
  end

  defp decode_tlv(_, _), do: {:error, :invalid_tlv}
end
