defmodule StrapCiphagile.Context.Hashing do
  alias StrapCiphagile.Context.Hashing

  use TypedStruct

  typedstruct do
    field(:version, any(), default: :v1_0)
    field(:algo, any())
    field(:variant, any())
    # Derived from variant (bytes)
    field(:hash_size, integer())
    # Optional
    field(:salt, any())
    # Optional
    field(:digest, any())
    # TLV 0xF0
    field(:misc, any())
  end

  @doc """
  Returns the hash output size in bytes for a given variant atom.
  Returns `nil` for unknown or variable-length variants.
  """
  def hash_size_for_variant(variant) do
    case variant do
      # SHA-2
      :sha2_224 -> 28
      :sha2_256 -> 32
      :sha2_384 -> 48
      :sha2_512 -> 64
      :sha2_512_224 -> 28
      :sha2_512_256 -> 32
      # SHA-3
      :sha3_224 -> 28
      :sha3_256 -> 32
      :sha3_384 -> 48
      :sha3_512 -> 64
      :sha3_512_224 -> 28
      :sha3_512_256 -> 32
      # PHOTON
      :photon_80 -> 10
      :photon_128 -> 16
      :photon_160 -> 20
      :photon_224 -> 28
      :photon_256 -> 32
      # SPONGENT
      :spongent_88 -> 11
      :spongent_128 -> 16
      :spongent_160 -> 20
      :spongent_224 -> 28
      :spongent_256 -> 32
      # RIPEMD
      :ripemd_128 -> 16
      :ripemd_160 -> 20
      :ripemd_256 -> 32
      :ripemd_320 -> 40
      # SM3
      :sm3 -> 32
      # ACSON
      :acson_128 -> 16
      :acson_128a -> 16
      :acson_hash256 -> 32
      :acson_xof128 -> nil
      :acson_cxof128 -> nil
      _ -> nil
    end
  end
end

alias StrapCiphagile.EncoderProtocol
alias StrapCiphagile.Context.Hashing

defimpl EncoderProtocol, for: Hashing do
  alias StrapCiphagile.Tags
  alias StrapCiphagile.VarLengthData

  def encode(%Hashing{} = hash, _opts) do
    # version:   1 byte  (default :v1_0 -> 0x01)
    # algo:      1 byte  (:sha2 -> 0x01)
    # variant:   1 byte  (:sha2_224 -> 0x01, etc)
    # hash_size: 1 byte big-endian (0x00 when nil / XOF)

    with {:ok, version_byte} <- encode_version(hash.version),
         {:ok, algo_byte} <- encode_algo(hash.algo),
         {:ok, variant_byte} <- encode_variant(hash.variant),
         {:ok, salt_data} <- VarLengthData.encode(hash.salt),
         {:ok, digest_data} <- VarLengthData.encode(hash.digest),
         {:ok, misc_data} <- VarLengthData.encode(hash.misc) do
      # hash_size: derive from variant if not explicitly set on the struct
      hash_size_val = hash.hash_size || Hashing.hash_size_for_variant(hash.variant) || 0

      # TLV Encoding: Tag + Value (Value includes Length spec handled by VarLengthData)
      # Skip if data is empty (nil or empty string -> VarLengthData returns <<>>)
      salt_chunk = if salt_data == <<>>, do: <<>>, else: <<0x01>> <> salt_data
      digest_chunk = if digest_data == <<>>, do: <<>>, else: <<0x02>> <> digest_data
      misc_chunk = if misc_data == <<>>, do: <<>>, else: <<0xF0>> <> misc_data

      res =
        <<version_byte, algo_byte, variant_byte, hash_size_val::unsigned-integer-size(8)>> <>
          salt_chunk <> digest_chunk <> misc_chunk

      with {:ok, full_data} <- VarLengthData.encode(res),
           {:ok, tag} <- Tags.tag_value(:hash_envp) do
        {:ok, <<tag>> <> full_data}
      else
        err -> err
      end
    else
      err -> err
    end
  end

  defp encode_version(:v1_0), do: {:ok, 0x01}
  defp encode_version(_), do: {:error, :unsupported_version}

  defp encode_algo(:sha2), do: {:ok, 0x01}
  defp encode_algo(:sha3), do: {:ok, 0x02}
  defp encode_algo(:photon), do: {:ok, 0x03}
  defp encode_algo(:spongent), do: {:ok, 0x04}
  defp encode_algo(:ripemd), do: {:ok, 0x05}
  defp encode_algo(:sm3), do: {:ok, 0x06}
  defp encode_algo(:acson), do: {:ok, 0x07}
  defp encode_algo(_), do: {:error, :unsupported_algo}

  defp encode_variant(:sha2_224), do: {:ok, 0x01}
  defp encode_variant(:sha2_256), do: {:ok, 0x02}
  defp encode_variant(:sha2_384), do: {:ok, 0x03}
  defp encode_variant(:sha2_512), do: {:ok, 0x04}
  defp encode_variant(:sha2_512_224), do: {:ok, 0x05}
  defp encode_variant(:sha2_512_256), do: {:ok, 0x06}

  defp encode_variant(:sha3_224), do: {:ok, 0x01}
  defp encode_variant(:sha3_256), do: {:ok, 0x02}
  defp encode_variant(:sha3_384), do: {:ok, 0x03}
  defp encode_variant(:sha3_512), do: {:ok, 0x04}
  defp encode_variant(:sha3_512_224), do: {:ok, 0x05}
  defp encode_variant(:sha3_512_256), do: {:ok, 0x06}

  defp encode_variant(:photon_80), do: {:ok, 0x01}
  defp encode_variant(:photon_128), do: {:ok, 0x02}
  defp encode_variant(:photon_160), do: {:ok, 0x03}
  defp encode_variant(:photon_224), do: {:ok, 0x04}
  defp encode_variant(:photon_256), do: {:ok, 0x05}

  defp encode_variant(:spongent_88), do: {:ok, 0x01}
  defp encode_variant(:spongent_128), do: {:ok, 0x02}
  defp encode_variant(:spongent_160), do: {:ok, 0x03}
  defp encode_variant(:spongent_224), do: {:ok, 0x04}
  defp encode_variant(:spongent_256), do: {:ok, 0x05}

  defp encode_variant(:ripemd_128), do: {:ok, 0x01}
  defp encode_variant(:ripemd_160), do: {:ok, 0x02}
  defp encode_variant(:ripemd_256), do: {:ok, 0x03}
  defp encode_variant(:ripemd_320), do: {:ok, 0x04}

  defp encode_variant(:sm3), do: {:ok, 0x00}

  defp encode_variant(:acson_128), do: {:ok, 0x01}
  defp encode_variant(:acson_128a), do: {:ok, 0x02}
  defp encode_variant(:acson_hash256), do: {:ok, 0x03}
  defp encode_variant(:acson_xof128), do: {:ok, 0x04}
  defp encode_variant(:acson_cxof128), do: {:ok, 0x05}

  defp encode_variant(_), do: {:error, :unsupported_variant}
end

alias StrapCiphagile.DecoderProtocol
alias StrapCiphagile.VarLengthData

defimpl DecoderProtocol, for: Hashing do
  def decode(%Hashing{} = _ctx, bin, _opts) do
    # Expect Tag 0x01 for Hashing
    with <<0x01, rest_after_tag::binary>> <- bin,
         {:ok, hashing_value, outer_rest} <- VarLengthData.decode(rest_after_tag),
         <<version_byte, algo_byte, variant_byte, hash_size_raw::unsigned-integer-size(8),
           inner_rest::binary>> <- hashing_value,
         {:ok, version} <- decode_version(version_byte),
         {:ok, algo} <- decode_algo(algo_byte),
         {:ok, variant} <- decode_variant(algo, variant_byte),
         hash_size = if(hash_size_raw == 0, do: nil, else: hash_size_raw),
         {:ok, final_struct} <-
           decode_tlv(inner_rest, %Hashing{
             version: version,
             algo: algo,
             variant: variant,
             hash_size: hash_size
           }) do
      if outer_rest == "" do
        {:ok, final_struct}
      else
        {:ok, {final_struct, outer_rest}}
      end
    else
      _ -> {:error, :decoding_failed}
    end
  end

  defp decode_tlv(<<>>, acc), do: {:ok, acc}

  # Tag 0x01: Salt
  defp decode_tlv(<<0x01, rest::binary>>, acc) do
    case VarLengthData.decode(rest) do
      {:ok, val, rest_after} -> decode_tlv(rest_after, %{acc | salt: val})
      err -> err
    end
  end

  # Tag 0x02: Digest
  defp decode_tlv(<<0x02, rest::binary>>, acc) do
    case VarLengthData.decode(rest) do
      {:ok, val, rest_after} -> decode_tlv(rest_after, %{acc | digest: val})
      err -> err
    end
  end

  # Tag 0xF0: Misc
  defp decode_tlv(<<0xF0, rest::binary>>, acc) do
    case VarLengthData.decode(rest) do
      {:ok, val, rest_after} -> decode_tlv(rest_after, %{acc | misc: val})
      err -> err
    end
  end

  defp decode_tlv(_, _), do: {:error, :invalid_tlv_structure}

  defp decode_version(0x01), do: {:ok, :v1_0}
  defp decode_version(_), do: {:error, :unknown_version}

  defp decode_algo(0x01), do: {:ok, :sha2}
  defp decode_algo(0x02), do: {:ok, :sha3}
  defp decode_algo(0x03), do: {:ok, :photon}
  defp decode_algo(0x04), do: {:ok, :spongent}
  defp decode_algo(0x05), do: {:ok, :ripemd}
  defp decode_algo(0x06), do: {:ok, :sm3}
  defp decode_algo(0x07), do: {:ok, :acson}
  defp decode_algo(_), do: {:error, :unknown_algo}

  defp decode_variant(:sha2, 0x01), do: {:ok, :sha2_224}
  defp decode_variant(:sha2, 0x02), do: {:ok, :sha2_256}
  defp decode_variant(:sha2, 0x03), do: {:ok, :sha2_384}
  defp decode_variant(:sha2, 0x04), do: {:ok, :sha2_512}
  defp decode_variant(:sha2, 0x05), do: {:ok, :sha2_512_224}
  defp decode_variant(:sha2, 0x06), do: {:ok, :sha2_512_256}

  defp decode_variant(:sha3, 0x01), do: {:ok, :sha3_224}
  defp decode_variant(:sha3, 0x02), do: {:ok, :sha3_256}
  defp decode_variant(:sha3, 0x03), do: {:ok, :sha3_384}
  defp decode_variant(:sha3, 0x04), do: {:ok, :sha3_512}
  defp decode_variant(:sha3, 0x05), do: {:ok, :sha3_512_224}
  defp decode_variant(:sha3, 0x06), do: {:ok, :sha3_512_256}

  defp decode_variant(:photon, 0x01), do: {:ok, :photon_80}
  defp decode_variant(:photon, 0x02), do: {:ok, :photon_128}
  defp decode_variant(:photon, 0x03), do: {:ok, :photon_160}
  defp decode_variant(:photon, 0x04), do: {:ok, :photon_224}
  defp decode_variant(:photon, 0x05), do: {:ok, :photon_256}

  defp decode_variant(:spongent, 0x01), do: {:ok, :spongent_88}
  defp decode_variant(:spongent, 0x02), do: {:ok, :spongent_128}
  defp decode_variant(:spongent, 0x03), do: {:ok, :spongent_160}
  defp decode_variant(:spongent, 0x04), do: {:ok, :spongent_224}
  defp decode_variant(:spongent, 0x05), do: {:ok, :spongent_256}

  defp decode_variant(:ripemd, 0x01), do: {:ok, :ripemd_128}
  defp decode_variant(:ripemd, 0x02), do: {:ok, :ripemd_160}
  defp decode_variant(:ripemd, 0x03), do: {:ok, :ripemd_256}
  defp decode_variant(:ripemd, 0x04), do: {:ok, :ripemd_320}

  defp decode_variant(:sm3, 0x00), do: {:ok, :sm3}

  defp decode_variant(:acson, 0x01), do: {:ok, :acson_128}
  defp decode_variant(:acson, 0x02), do: {:ok, :acson_128a}
  defp decode_variant(:acson, 0x03), do: {:ok, :acson_hash256}
  defp decode_variant(:acson, 0x04), do: {:ok, :acson_xof128}
  defp decode_variant(:acson, 0x05), do: {:ok, :acson_cxof128}

  defp decode_variant(_, _), do: {:error, :unknown_variant}
end
