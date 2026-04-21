defmodule StrapCiphagile.Context.Symkey do
  use TypedStruct

  typedstruct do
    field(:version, any(), default: :v1_0)
    # AES : 0x01
    # Camelia : 0x02
    # CLEFIA : 0x03
    # SEED : 0x04
    # HEIGHT : 0x08
    # PRESENT : 0x09
    # Deoxys-TBC : 0x10
    # Skinny : 0x11
    # XTS-AES : 0x12
    # Chacha20 : 0x20
    # HC : 0x21
    # Kcipher-2 : 0x22
    # MUGI : 0x23
    # Rabbit: 0x24
    field(:algo, any())
    # AES-128 : 0x01
    # AES-192 : 0x02
    # AES-256 : 0x03
    # Camelia-128 : 0x01
    # Camelia-192 : 0x02
    # Camelia-256 : 0x03
    field(:variant, any())

    field(:keysize, any())

    # Optional
    # TLV encode
    # tag = 0x01
    field(:kdf_config, any())
    # Optional
    # tag = 0x02
    field(:raw_key, any())
    # TLV 0xF0
    field(:misc, any())
  end

  def new(algo, variant \\ -1) do
    %__MODULE__{
      version: :v1_0,
      algo: algo,
      variant: variant,
      keysize: expected_key_size_bits(algo, variant)
    }
  end

  def expected_key_size_bytes(_, variant) when variant in [:aes_128, :camelia_128], do: 16
  def expected_key_size_bytes(_, variant) when variant in [:aes_192, :camelia_192], do: 24
  def expected_key_size_bytes(_, variant) when variant in [:aes_256, :camelia_256], do: 32
  def expected_key_size_bytes(:chacha20, _), do: 32
  def expected_key_size_bytes(_, _), do: :any

  def expected_key_size_bits(algo, variant) do
    case expected_key_size_bytes(algo, variant) do
      :any -> :any
      bytes -> bytes * 8
    end
  end
end

alias StrapCiphagile.EncoderProtocol
alias StrapCiphagile.DecoderProtocol
alias StrapCiphagile.VarLengthData
alias StrapCiphagile.Context.Symkey
alias StrapCiphagile.Context.KDF

defimpl EncoderProtocol, for: Symkey do
  alias StrapCiphagile.Tags

  def encode(%Symkey{} = ctx, _opts) do
    with :ok <- validate_key_size(ctx.algo, ctx.variant, ctx.raw_key),
         :ok <- validate_kdf_size(ctx.algo, ctx.variant, ctx.kdf_config),
         {:ok, version_byte} <- encode_version(ctx.version),
         {:ok, algo_byte} <- encode_algo(ctx.algo),
         {:ok, variant_byte} <- encode_variant(ctx.variant),
         {:ok, kdf_bin} <- encode_tlv(0x01, ctx.kdf_config),
         {:ok, key_bin} <- encode_tlv(0x02, ctx.raw_key),
         {:ok, misc_bin} <- encode_tlv(0xF0, ctx.misc) do
      content = <<version_byte, algo_byte, variant_byte>> <> kdf_bin <> key_bin <> misc_bin

      with {:ok, full_data} <- VarLengthData.encode(content),
           {:ok, tag} <- Tags.tag_value(:secret_key_envp) do
        {:ok, <<tag>> <> full_data}
      else
        err -> err
      end
    else
      err -> err
    end
  end

  defp validate_key_size(_algo, _variant, nil), do: :ok

  # AES / Camellia variants
  defp validate_key_size(_, variant, key)
       when variant in [:aes_128, :camelia_128] and byte_size(key) == 16,
       do: :ok

  defp validate_key_size(_, variant, key)
       when variant in [:aes_192, :camelia_192] and byte_size(key) == 24,
       do: :ok

  defp validate_key_size(_, variant, key)
       when variant in [:aes_256, :camelia_256] and byte_size(key) == 32,
       do: :ok

  # ChaCha20 usually 256 bits (32 bytes)
  defp validate_key_size(:chacha20, _, key) when byte_size(key) == 32, do: :ok

  defp validate_key_size(_algo, _variant, nil), do: :ok

  defp validate_key_size(algo, variant, key),
    do: {:error, {:invalid_key_size, algo, variant, byte_size(key) * 8}}

  # defp validate_kdf_size(_, variant, key),
  #  do: {:error, {:invalid_key_size, variant, byte_size(key)}}

  defp validate_kdf_size(_algo, _variant, nil), do: :ok

  defp validate_kdf_size(algo, variant, %KDF{kdf_config: config}) when not is_nil(config) do
    out_len = get_out_length(config)

    # Reuse the same size logic, pass a dummy binary of checks size
    # Or just check numbers directly
    expected_size = Symkey.expected_key_size_bytes(algo, variant)

    # If out_len is nil or 0, maybe we skip? Or enforce if present?
    # Usually KDF must produce the key, so it must match.
    if out_len == expected_size do
      :ok
    else
      if expected_size == :any do
        :ok
      else
        {:error, :invalid_kdf_output_size}
      end
    end
  end

  # KDF struct but no config? or other cases
  defp validate_kdf_size(_, _, _), do: :ok

  defp get_out_length(%{out_length: val}) when is_integer(val), do: val

  defp get_out_length(%{out_length: "0x" <> hex_str}) do
    case Integer.parse(hex_str, 16) do
      {int, ""} -> int
      _ -> 0
    end
  end

  defp get_out_length(%{out_length: val}) when is_binary(val) do
    # Try parsing as decimal string first
    case Integer.parse(val) do
      {int, ""} ->
        int

      _ ->
        # If not a string, treat as raw binary value (e.g. <<16>>)
        try do
          :binary.decode_unsigned(val)
        rescue
          _ -> 0
        end
    end
  end

  defp get_out_length(_), do: 0

  defp encode_version(:v1_0), do: {:ok, 0x01}
  defp encode_version(_), do: {:error, :unsupported_version}

  defp encode_algo(:aes), do: {:ok, 0x01}
  defp encode_algo(:camelia), do: {:ok, 0x02}
  defp encode_algo(:clefia), do: {:ok, 0x03}
  defp encode_algo(:seed), do: {:ok, 0x04}
  defp encode_algo(:height), do: {:ok, 0x08}
  defp encode_algo(:present), do: {:ok, 0x09}
  defp encode_algo(:deoxys_tbc), do: {:ok, 0x10}
  defp encode_algo(:skinny), do: {:ok, 0x11}
  defp encode_algo(:xts_aes), do: {:ok, 0x12}
  defp encode_algo(:chacha20), do: {:ok, 0x20}
  defp encode_algo(:hc), do: {:ok, 0x21}
  defp encode_algo(:kcipher_2), do: {:ok, 0x22}
  defp encode_algo(:mugi), do: {:ok, 0x23}
  defp encode_algo(:rabbit), do: {:ok, 0x24}
  defp encode_algo(_), do: {:error, :unknown_algo}

  defp encode_variant(:aes_128), do: {:ok, 0x01}
  defp encode_variant(:camelia_128), do: {:ok, 0x01}
  defp encode_variant(:aes_192), do: {:ok, 0x02}
  defp encode_variant(:camelia_192), do: {:ok, 0x02}
  defp encode_variant(:aes_256), do: {:ok, 0x03}
  defp encode_variant(:camelia_256), do: {:ok, 0x03}

  defp encode_variant(:chacha20), do: {:ok, 0x01}
  # Allow raw integers if needed
  defp encode_variant(val) when is_integer(val), do: {:ok, val}
  defp encode_variant(_), do: {:error, :unknown_variant}

  defp encode_tlv(_tag, nil), do: {:ok, <<>>}
  defp encode_tlv(_tag, ""), do: {:ok, <<>>}

  # For KDF struct, encode it using its protocol first
  defp encode_tlv(0x01, %KDF{} = kdf) do
    with {:ok, encoded_kdf} <- EncoderProtocol.encode(kdf) do
      # KDF encoding already includes its own tag/length wrapper (0x02 + Len + Content)
      # Do we wrap it again?
      # "Uses EncoderProtocol.encode(kdf_config) which returns a binary starting with its own tag/length, but here we wrap it in 0x01 + VarLength"
      # Yes, standard TLV wrapper for the field in Symkey.
      with {:ok, len_val} <- VarLengthData.encode(encoded_kdf) do
        {:ok, <<0x01>> <> len_val}
      end
    end
  end

  # For raw key (binary)
  defp encode_tlv(tag, val) when is_binary(val) do
    with {:ok, encoded} <- VarLengthData.encode(val) do
      {:ok, <<tag>> <> encoded}
    else
      err -> err
    end
  end

  defp encode_tlv(_, _), do: {:error, :invalid_tlv_value}
end

defimpl DecoderProtocol, for: Symkey do
  def decode(%Symkey{} = _ctx, bin, _opts) do
    with <<0x10, rest_after_tag::binary>> <- bin,
         {:ok, content, outer_rest} <- VarLengthData.decode(rest_after_tag),
         <<version_byte, algo_byte, variant_byte, inner_rest::binary>> <- content,
         {:ok, version} <- decode_version(version_byte),
         {:ok, algo} <- decode_algo(algo_byte),
         {:ok, variant} <- decode_variant(algo, variant_byte),
         {:ok, symkey_struct} <-
           decode_tlv(inner_rest, %Symkey{
             version: version,
             algo: algo,
             variant: variant,
             keysize: Symkey.expected_key_size_bits(algo, variant)
           }) do
      if outer_rest == "" do
        {:ok, symkey_struct}
      else
        {:ok, {symkey_struct, outer_rest}}
      end
    else
      _ -> {:error, :decoding_failed}
    end
  end

  defp decode_version(0x01), do: {:ok, :v1_0}
  defp decode_version(_), do: {:error, :unknown_version}

  defp decode_algo(0x01), do: {:ok, :aes}
  defp decode_algo(0x02), do: {:ok, :camelia}
  defp decode_algo(0x03), do: {:ok, :clefia}
  defp decode_algo(0x04), do: {:ok, :seed}
  defp decode_algo(0x08), do: {:ok, :height}
  defp decode_algo(0x09), do: {:ok, :present}
  defp decode_algo(0x10), do: {:ok, :deoxys_tbc}
  defp decode_algo(0x11), do: {:ok, :skinny}
  defp decode_algo(0x12), do: {:ok, :xts_aes}
  defp decode_algo(0x20), do: {:ok, :chacha20}
  defp decode_algo(0x21), do: {:ok, :hc}
  defp decode_algo(0x22), do: {:ok, :kcipher_2}
  defp decode_algo(0x23), do: {:ok, :mugi}
  defp decode_algo(0x24), do: {:ok, :rabbit}
  defp decode_algo(_), do: {:error, :unknown_algo}

  defp decode_variant(:aes, 0x01), do: {:ok, :aes_128}
  defp decode_variant(:aes, 0x02), do: {:ok, :aes_192}
  defp decode_variant(:aes, 0x03), do: {:ok, :aes_256}

  defp decode_variant(:camelia, 0x01), do: {:ok, :camelia_128}
  defp decode_variant(:camelia, 0x02), do: {:ok, :camelia_192}
  defp decode_variant(:camelia, 0x03), do: {:ok, :camelia_256}

  defp decode_variant(:chacha20, 0x01), do: {:ok, :chacha20}

  # Fallback to int if needed or generic
  defp decode_variant(_, val), do: {:ok, val}

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  # KDF Config (0x01)
  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    with {:ok, kdf_outer_bin, rest_after} <- VarLengthData.decode(rest),
         # Recursively decode the KDF struct from the inner binary
         {:ok, kdf_struct} <- DecoderProtocol.decode(%KDF{}, kdf_outer_bin) do
      decode_tlv(rest_after, %{acc | kdf_config: kdf_struct})
    end
  end

  # Raw Key (0x02)
  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | raw_key: val})
    end
  end

  # Misc (0xF0)
  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    with {:ok, val, rest_after} <- VarLengthData.decode(rest) do
      decode_tlv(rest_after, %{acc | misc: val})
    end
  end

  defp decode_tlv(_, _), do: {:error, :invalid_tlv}
end
