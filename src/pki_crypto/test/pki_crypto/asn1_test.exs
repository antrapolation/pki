defmodule PkiCrypto.Asn1Test do
  use ExUnit.Case, async: true

  alias PkiCrypto.Asn1

  describe "integer/1" do
    test "small positive integer" do
      assert <<0x02, 0x01, 0x05>> = Asn1.integer(5)
    end

    test "zero" do
      assert <<0x02, 0x01, 0x00>> = Asn1.integer(0)
    end

    test "high-bit set requires leading zero" do
      assert <<0x02, 0x02, 0x00, 0x80>> = Asn1.integer(128)
    end

    test "two-byte value" do
      assert <<0x02, 0x02, 0x01, 0x00>> = Asn1.integer(256)
    end
  end

  describe "oid/1" do
    test "encodes {1, 2, 840, 10045, 4, 3, 2} (ecdsa-with-SHA256)" do
      assert <<0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>> =
               Asn1.oid({1, 2, 840, 10045, 4, 3, 2})
    end

    test "encodes large subidentifier via base-128" do
      assert <<0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x01, 0x01>> =
               Asn1.oid({1, 3, 6, 1, 4, 1, 99999, 1, 1, 1})
    end
  end

  describe "octet_string/1" do
    test "short" do
      assert <<0x04, 0x03, 0x01, 0x02, 0x03>> = Asn1.octet_string(<<1, 2, 3>>)
    end

    test "empty" do
      assert <<0x04, 0x00>> = Asn1.octet_string(<<>>)
    end
  end

  describe "bit_string/1" do
    test "wraps content with unused-bits byte 0" do
      assert <<0x03, 0x04, 0x00, 0xAA, 0xBB, 0xCC>> = Asn1.bit_string(<<0xAA, 0xBB, 0xCC>>)
    end
  end

  describe "boolean/1" do
    test "true is 0xFF" do
      assert <<0x01, 0x01, 0xFF>> = Asn1.boolean(true)
    end

    test "false is 0x00" do
      assert <<0x01, 0x01, 0x00>> = Asn1.boolean(false)
    end
  end

  describe "null/0" do
    test "is 05 00" do
      assert <<0x05, 0x00>> = Asn1.null()
    end
  end

  describe "utc_time/1" do
    test "encodes as YYMMDDHHMMSSZ" do
      dt = ~U[2026-04-15 14:30:00Z]
      assert <<0x17, 0x0D, "260415143000Z">> = Asn1.utc_time(dt)
    end
  end

  describe "generalized_time/1" do
    test "encodes as YYYYMMDDHHMMSSZ" do
      dt = ~U[2050-04-15 14:30:00Z]
      assert <<0x18, 0x0F, "20500415143000Z">> = Asn1.generalized_time(dt)
    end
  end

  describe "length encoding (via sequence wrapping)" do
    test "short form length" do
      assert <<0x30, 0x03, 0xAA, 0xBB, 0xCC>> = Asn1.sequence([<<0xAA, 0xBB, 0xCC>>])
    end

    test "long form length for >127 byte body" do
      body = :binary.copy(<<0xAA>>, 200)
      assert <<0x30, 0x81, 0xC8, ^body::binary>> = Asn1.sequence([body])
    end

    test "long form length for >255 byte body" do
      body = :binary.copy(<<0xAA>>, 300)
      assert <<0x30, 0x82, 0x01, 0x2C, ^body::binary>> = Asn1.sequence([body])
    end
  end

  describe "read_integer/1" do
    test "reads small positive integer" do
      assert {5, ""} = Asn1.read_integer(<<0x02, 0x01, 0x05>>)
    end

    test "reads with leading zero" do
      assert {128, ""} = Asn1.read_integer(<<0x02, 0x02, 0x00, 0x80>>)
    end

    test "returns remainder after the integer" do
      assert {5, <<0xFF>>} = Asn1.read_integer(<<0x02, 0x01, 0x05, 0xFF>>)
    end
  end

  describe "read_oid/1" do
    test "reads ecdsa-with-SHA256" do
      assert {{1, 2, 840, 10045, 4, 3, 2}, ""} =
               Asn1.read_oid(<<0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>>)
    end

    test "reads large subidentifier" do
      assert {{1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}, ""} =
               Asn1.read_oid(<<0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x01, 0x01>>)
    end
  end

  describe "read_bit_string/1" do
    test "reads content, strips unused-bits byte" do
      assert {<<0xAA, 0xBB, 0xCC>>, ""} = Asn1.read_bit_string(<<0x03, 0x04, 0x00, 0xAA, 0xBB, 0xCC>>)
    end
  end

  describe "read_octet_string/1" do
    test "reads raw bytes" do
      assert {<<1, 2, 3>>, ""} = Asn1.read_octet_string(<<0x04, 0x03, 0x01, 0x02, 0x03>>)
    end
  end

  describe "read_sequence/1" do
    test "reads body and returns remainder" do
      input = <<0x30, 0x03, 0xAA, 0xBB, 0xCC, 0xFF, 0xFF>>
      assert {<<0xAA, 0xBB, 0xCC>>, <<0xFF, 0xFF>>} = Asn1.read_sequence(input)
    end
  end

  describe "read_sequence_items/1" do
    test "splits a sequence body into constituent DER elements" do
      body = <<0x02, 0x01, 0x05>> <> <<0x04, 0x03, "abc">>
      assert [<<0x02, 0x01, 0x05>>, <<0x04, 0x03, ?a, ?b, ?c>>] = Asn1.read_sequence_items(body)
    end

    test "returns empty list for empty body" do
      assert [] = Asn1.read_sequence_items(<<>>)
    end
  end

  describe "round-trip" do
    test "integer" do
      for n <- [0, 1, 127, 128, 255, 256, 65535, 65536, 1_000_000] do
        {decoded, ""} = Asn1.read_integer(Asn1.integer(n))
        assert decoded == n, "failed for #{n}"
      end
    end

    test "oid" do
      oids = [
        {1, 2, 840, 113549, 1, 1, 11},
        {2, 16, 840, 1, 101, 3, 4, 3, 17},
        {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}
      ]

      for o <- oids do
        {decoded, ""} = Asn1.read_oid(Asn1.oid(o))
        assert decoded == o
      end
    end

    test "bit_string" do
      bs = <<0xDE, 0xAD, 0xBE, 0xEF>>
      {decoded, ""} = Asn1.read_bit_string(Asn1.bit_string(bs))
      assert decoded == bs
    end

    test "octet_string" do
      os = <<1, 2, 3, 4, 5>>
      {decoded, ""} = Asn1.read_octet_string(Asn1.octet_string(os))
      assert decoded == os
    end
  end
end
