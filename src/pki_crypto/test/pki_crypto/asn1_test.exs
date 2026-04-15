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
end
