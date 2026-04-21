defmodule StrapCiphagile.Context.HashingTest do
  use ExUnit.Case
  alias StrapCiphagile.Context.Hashing
  alias StrapCiphagile.EncoderProtocol
  alias StrapCiphagile.DecoderProtocol
  alias StrapCiphagile.VarLengthData

  # Parses TLV fields from binary in any order, returning %{tag => value}
  defp parse_tlv_fields(binary, acc \\ %{})
  defp parse_tlv_fields("", acc), do: acc

  defp parse_tlv_fields(<<tag, rest::binary>>, acc) do
    {:ok, value, remaining} = VarLengthData.decode(rest)
    parse_tlv_fields(remaining, Map.put(acc, tag, value))
  end

  test "encode and decode sha2_256 with digest and salt" do
    salt = :crypto.strong_rand_bytes(16)
    digest = :crypto.strong_rand_bytes(32)

    hash = %Hashing{
      version: :v1_0,
      algo: :sha2,
      variant: :sha2_256,
      salt: salt,
      digest: digest
    }

    assert {:ok, encoded} = EncoderProtocol.encode(hash)
    assert is_binary(encoded)

    # Verify outer structure: Tag(0x01) + VarLengthData(Value)
    assert <<0x01, outer_rest::binary>> = encoded
    {:ok, hashing_value, ""} = VarLengthData.decode(outer_rest)

    inner_rest =
      case hashing_value do
        # Verify inner structure
        # Version (1) + Algo (1) + Variant (1) + HashSize (1 byte)
        # sha2_256 -> 32 bytes = 0x20
        <<0x01, 0x01, 0x02, 0x20, inner_rest::binary>> ->
          IO.puts("version 1.0 of hash struct")
          inner_rest

        _ ->
          flunk("version 1.0 hash struct only supported")
      end

    # Parse TLV fields in any order
    tlv_fields = parse_tlv_fields(inner_rest)
    assert tlv_fields[0x01] == salt
    assert tlv_fields[0x02] == digest
    assert map_size(tlv_fields) == 2

    # Decode back
    assert {:ok, decoded_hash} = DecoderProtocol.decode(%Hashing{}, encoded)
    # hash_size is derived from variant during encoding (32 bytes for sha2_256)
    assert decoded_hash == %{hash | hash_size: 32}
  end

  test "decode out of order (Digest then Salt)" do
    salt = "SALT"
    digest = "DIGEST"

    # Inner Hashing Value: Header + Tag2(Digest) + Tag1(Salt)
    # v1, sha2, sha2_256, hash_size=32 bytes (0x20)
    header = <<0x01, 0x01, 0x02, 0x20>>

    # Digest: Tag 0x02 + VarLen(DIGEST)
    {:ok, digest_data} = VarLengthData.encode(digest)
    digest_chunk = <<0x02>> <> digest_data

    # Salt: Tag 0x01 + VarLen(SALT)
    {:ok, salt_data} = VarLengthData.encode(salt)
    salt_chunk = <<0x01>> <> salt_data

    inner_value = header <> digest_chunk <> salt_chunk

    # Wrap in Outer TLV: Tag 0x01 + VarLen(inner_value)
    {:ok, inner_enocded} = VarLengthData.encode(inner_value)
    payload = <<0x01>> <> inner_enocded

    assert {:ok, decoded} = DecoderProtocol.decode(%Hashing{}, payload)
    assert decoded.salt == salt
    assert decoded.digest == digest
  end

  test "encode and decode optional salt/digest (nil)" do
    hash = %Hashing{
      version: :v1_0,
      algo: :sha2,
      variant: :sha2_512,
      salt: nil,
      digest: nil
    }

    assert {:ok, encoded} = EncoderProtocol.encode(hash)

    # Structure: Tag 0x01 + VarLen(4 bytes: ver/algo/var/hash_size)
    # VarLength(4 bytes) -> 0x01 + 0x04 + data
    # Total: 1 (Tag) + 1 (LenSpec) + 1 (Len) + 4 (Data) = 7 bytes
    # sha2_512 -> 64 bytes = 0x40
    assert byte_size(encoded) == 7

    assert <<0x01, 0x01, 0x04, 0x01, 0x01, 0x04, 0x40>> = encoded

    assert {:ok, decoded} = DecoderProtocol.decode(%Hashing{}, encoded)
    assert decoded.salt == nil
    assert decoded.digest == nil
  end

  test "VarLengthData boundary checks" do
    # 255 bytes -> 0x01, 0xFF, data
    data255 = :binary.copy(<<0xAA>>, 255)
    assert {:ok, enc} = VarLengthData.encode(data255)
    assert <<0x01, 0xFF, _::binary>> = IO.iodata_to_binary(enc)

    # 256 bytes -> 0x02, 0x01, 0x00, data (2 bytes length)
    data256 = :binary.copy(<<0xAA>>, 256)
    assert {:ok, enc} = VarLengthData.encode(data256)
    assert <<0x02, 0x01, 0x00, _::binary>> = IO.iodata_to_binary(enc)
  end

  test "encode and decode using StrapCiphagile module" do
    hash = %Hashing{
      version: :v1_0,
      algo: :sha2,
      variant: :sha2_256,
      salt: "somesalt",
      digest: "somedigest"
    }

    assert {:ok, encoded} = StrapCiphagile.encode(hash)
    assert is_binary(encoded)
    assert <<0xAF, 0x08, 0x01, _::binary>> = encoded

    assert {:ok, decoded} = StrapCiphagile.decode(encoded)
    # hash_size is derived from variant during encoding (32 bytes for sha2_256)
    assert decoded == %{hash | hash_size: 32}
  end

  test "decode with random data at the back" do
    hash = %Hashing{
      version: :v1_0,
      algo: :sha2,
      variant: :sha2_256,
      salt: "salt",
      digest: "digest"
    }

    {:ok, encoded} = EncoderProtocol.encode(hash)
    random_garbage = :crypto.strong_rand_bytes(10)
    full_binary = encoded <> random_garbage

    # DecoderProtocol returns {:ok, {struct, rest}} if rest not empty
    assert {:ok, {decoded_hash, rest}} = DecoderProtocol.decode(%Hashing{}, full_binary)
    # hash_size is derived from variant during encoding (32 bytes for sha2_256)
    assert decoded_hash == %{hash | hash_size: 32}
    assert rest == random_garbage
  end

  describe "SHA3 Support" do
    setup do
      salt = :crypto.strong_rand_bytes(16)
      data = "some test data"
      %{salt: salt, data: data}
    end

    for {variant, variant_byte, algo_atom} <- [
          {:sha3_224, 0x01, :sha3_224},
          {:sha3_256, 0x02, :sha3_256},
          {:sha3_384, 0x03, :sha3_384},
          {:sha3_512, 0x04, :sha3_512}
        ] do
      test "encode and decode #{variant} with ExCcrypto digest", %{salt: salt, data: data} do
        # Use ExCcrypto to generate the hash
        ctx = %ExCcrypto.Digest.DigestContext{algo: unquote(algo_atom)}

        # We append salt to data just to have some deterministic hash inputs for our test
        {:ok, %{digested: actual_digest}} = ExCcrypto.Digest.digest(ctx, data <> salt)

        hash = %Hashing{
          version: :v1_0,
          algo: :sha3,
          variant: unquote(variant),
          salt: salt,
          digest: actual_digest
        }

        assert {:ok, encoded} = EncoderProtocol.encode(hash)

        # Verify outer structure: Tag(0x01) + VarLengthData(Value)
        assert <<0x01, outer_rest::binary>> = encoded
        {:ok, hashing_value, ""} = VarLengthData.decode(outer_rest)

        # Verify inner structure
        # Version (1) + Algo (2 for :sha3) + Variant (1) + HashSize (1 byte)
        variant_byte = unquote(variant_byte)

        assert <<0x01, 0x02, ^variant_byte, _hash_size::unsigned-integer-size(8),
                 inner_rest::binary>> = hashing_value

        # Parse TLV fields in any order
        tlv_fields = parse_tlv_fields(inner_rest)
        assert tlv_fields[0x01] == salt
        assert tlv_fields[0x02] == actual_digest

        # Decode back
        assert {:ok, decoded_hash} = DecoderProtocol.decode(%Hashing{}, encoded)
        # hash_size is derived from variant during encoding
        expected_hash_size = Hashing.hash_size_for_variant(unquote(variant))
        assert decoded_hash == %{hash | hash_size: expected_hash_size}
      end
    end
  end

  describe "Comprehensive Hash Encoding Matrix" do
    for {algo, variant, expected_algo_byte, expected_variant_byte} <- [
          # SHA2
          {:sha2, :sha2_224, 0x01, 0x01},
          {:sha2, :sha2_256, 0x01, 0x02},
          {:sha2, :sha2_512_256, 0x01, 0x06},

          # SHA3
          {:sha3, :sha3_224, 0x02, 0x01},
          {:sha3, :sha3_512_256, 0x02, 0x06},

          # PHOTON
          {:photon, :photon_80, 0x03, 0x01},
          {:photon, :photon_256, 0x03, 0x05},

          # SPONGENT
          {:spongent, :spongent_88, 0x04, 0x01},
          {:spongent, :spongent_256, 0x04, 0x05},

          # RIPEMD
          {:ripemd, :ripemd_128, 0x05, 0x01},
          {:ripemd, :ripemd_320, 0x05, 0x04},

          # SM3
          {:sm3, :sm3, 0x06, 0x00},

          # ACSON
          {:acson, :acson_128, 0x07, 0x01},
          {:acson, :acson_cxof128, 0x07, 0x05}
        ] do
      test "encode and decode structure for #{algo} -> #{variant}" do
        hash = %Hashing{
          version: :v1_0,
          algo: unquote(algo),
          variant: unquote(variant),
          salt: nil,
          digest: "fake_digest"
        }

        assert {:ok, encoded} = EncoderProtocol.encode(hash)

        # Verify outer structure: Tag(0x01) + VarLengthData(Value)
        assert <<0x01, outer_rest::binary>> = encoded
        {:ok, hashing_value, ""} = VarLengthData.decode(outer_rest)

        expected_algo = unquote(expected_algo_byte)
        expected_variant = unquote(expected_variant_byte)

        assert <<0x01, ^expected_algo, ^expected_variant, _hash_size::unsigned-integer-size(8),
                 inner_rest::binary>> = hashing_value

        # We encoded digest but no salt — parse TLV fields in any order
        tlv_fields = parse_tlv_fields(inner_rest)
        assert tlv_fields[0x02] == "fake_digest"
        assert is_nil(tlv_fields[0x01])

        # Verify decode Protocol
        assert {:ok, decoded_hash} = DecoderProtocol.decode(%Hashing{}, encoded)
        # hash_size is derived from variant during encoding
        expected_hash_size = Hashing.hash_size_for_variant(unquote(variant))
        assert decoded_hash == %{hash | hash_size: expected_hash_size}
      end
    end
  end
end
