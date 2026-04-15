defmodule PkiCrypto.Asn1 do
  @moduledoc """
  DER primitive encoder for X.509/PKCS#10 fields the `:public_key` library
  does not expose directly — specifically for emitting structures that
  carry non-classical algorithm OIDs in `subjectPublicKeyInfo` and
  `signatureAlgorithm`.

  Only the subset of ASN.1 DER needed by X.509 v3 + PKCS#10 is covered:
  INTEGER, OCTET STRING, BIT STRING, OBJECT IDENTIFIER, BOOLEAN, NULL,
  UTCTime, GeneralizedTime, SEQUENCE, SET, and context-tagged wrappers.

  All encoders return DER bytes suitable for concatenation into parent
  structures. Parsers (`read_*`) are added in Task 2.
  """

  import Bitwise

  # --- Encoders ---

  @doc "Encode a non-negative integer as DER INTEGER."
  @spec integer(non_neg_integer()) :: binary()
  def integer(n) when is_integer(n) and n >= 0 do
    bytes = :binary.encode_unsigned(n)

    bytes =
      case bytes do
        <<b, _::binary>> when b >= 0x80 -> <<0x00, bytes::binary>>
        _ -> bytes
      end

    <<0x02, byte_size(bytes)>> <> bytes
  end

  @doc "Encode a tuple-of-arcs OID as DER OBJECT IDENTIFIER."
  @spec oid(tuple()) :: binary()
  def oid(oid_tuple) when is_tuple(oid_tuple) do
    [a1, a2 | rest] = Tuple.to_list(oid_tuple)
    first_byte = a1 * 40 + a2

    tail_bytes =
      rest
      |> Enum.flat_map(&encode_base128/1)

    content = IO.iodata_to_binary([first_byte | tail_bytes])
    <<0x06, byte_size(content)>> <> content
  end

  @doc "Encode raw bytes as DER OCTET STRING."
  @spec octet_string(binary()) :: binary()
  def octet_string(bytes) when is_binary(bytes) do
    <<0x04>> <> encode_length(byte_size(bytes)) <> bytes
  end

  @doc """
  Encode raw bytes as DER BIT STRING with an implicit leading `unused bits = 0` byte.
  Use this when the content is an aligned byte stream (the common case for X.509).
  """
  @spec bit_string(binary()) :: binary()
  def bit_string(bytes) when is_binary(bytes) do
    content = <<0x00, bytes::binary>>
    <<0x03>> <> encode_length(byte_size(content)) <> content
  end

  @doc "Encode a BOOLEAN."
  @spec boolean(boolean()) :: binary()
  def boolean(true), do: <<0x01, 0x01, 0xFF>>
  def boolean(false), do: <<0x01, 0x01, 0x00>>

  @doc "Encode NULL."
  @spec null() :: binary()
  def null, do: <<0x05, 0x00>>

  @doc "Encode a UTCTime (valid for dates 1950-2049)."
  @spec utc_time(DateTime.t()) :: binary()
  def utc_time(%DateTime{} = dt) do
    yy = rem(dt.year, 100)

    formatted =
      :io_lib.format("~2..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ", [
        yy,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second
      ])

    content = IO.iodata_to_binary(formatted)
    <<0x17, byte_size(content)>> <> content
  end

  @doc "Encode a GeneralizedTime (used for dates >= 2050)."
  @spec generalized_time(DateTime.t()) :: binary()
  def generalized_time(%DateTime{} = dt) do
    formatted =
      :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ", [
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second
      ])

    content = IO.iodata_to_binary(formatted)
    <<0x18, byte_size(content)>> <> content
  end

  @doc "Wrap a list of DER-encoded items in a SEQUENCE."
  @spec sequence([binary()]) :: binary()
  def sequence(items) when is_list(items) do
    body = IO.iodata_to_binary(items)
    <<0x30>> <> encode_length(byte_size(body)) <> body
  end

  @doc "Wrap a list of DER-encoded items in a SET."
  @spec set([binary()]) :: binary()
  def set(items) when is_list(items) do
    body = IO.iodata_to_binary(items)
    <<0x31>> <> encode_length(byte_size(body)) <> body
  end

  @doc """
  Wrap DER content in a context-specific tagged value.

  `:explicit` wraps existing DER bytes inside the tag (used for X.509 `[0]` version
  and `[3]` extensions). `:implicit` replaces the outer tag byte.
  """
  @spec tagged(0..30, :explicit | :implicit, binary()) :: binary()
  def tagged(tag, :explicit, content) when tag in 0..30 and is_binary(content) do
    outer_tag = 0xA0 ||| tag
    <<outer_tag>> <> encode_length(byte_size(content)) <> content
  end

  def tagged(tag, :implicit, <<_old_tag, rest::binary>>) when tag in 0..30 do
    outer_tag = 0x80 ||| tag
    {body, _after} = take_length_prefixed(rest)
    <<outer_tag>> <> encode_length(byte_size(body)) <> body
  end

  # --- Length helpers ---

  @doc false
  def encode_length(n) when n < 128, do: <<n>>
  def encode_length(n) when n < 256, do: <<0x81, n>>
  def encode_length(n) when n < 65_536, do: <<0x82, n::16>>
  def encode_length(n) when n < 16_777_216, do: <<0x83, n::24>>

  defp take_length_prefixed(<<n, rest::binary>>) when n < 128 do
    <<body::binary-size(n), after_body::binary>> = rest
    {body, after_body}
  end

  defp take_length_prefixed(<<0x81, n, rest::binary>>) do
    <<body::binary-size(n), after_body::binary>> = rest
    {body, after_body}
  end

  defp take_length_prefixed(<<0x82, n::16, rest::binary>>) do
    <<body::binary-size(n), after_body::binary>> = rest
    {body, after_body}
  end

  defp take_length_prefixed(<<0x83, n::24, rest::binary>>) do
    <<body::binary-size(n), after_body::binary>> = rest
    {body, after_body}
  end

  # --- base-128 encoding for OID sub-identifiers ---
  # Produces 7-bit groups MSB-first. All but the last byte get the continuation bit (0x80).

  defp encode_base128(n) when n < 128, do: [n]

  defp encode_base128(n) do
    groups =
      Stream.unfold(n, fn
        0 -> nil
        x -> {rem(x, 128), div(x, 128)}
      end)
      |> Enum.reverse()

    {init, [last]} = Enum.split(groups, -1)
    Enum.map(init, &(&1 ||| 0x80)) ++ [last]
  end
end
