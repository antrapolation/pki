# Phase 2 — Classical Issuer, PQC Subject (Cross-Algorithm Signing) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable a classical CA (RSA/ECDSA) to sign a sub-CA or leaf certificate whose public key is PQC (ML-DSA or KAZ-SIGN). Output is real RFC 5280 X.509. Retires the hardcoded family-specific signing logic in `PkiCaEngine.CertificateSigning` for the classical-issuer path.

**Architecture:** Three new modules in `pki_crypto`: `PkiCrypto.Asn1` (DER primitive encoder/decoder), `PkiCrypto.Csr` (PKCS#10 parse + verify + generate with cross-algo support), `PkiCrypto.X509Builder` (TBS cert construction + classical signing). `PkiCaEngine.CertificateSigning.issue/5` becomes a thin orchestrator on top. Classical→classical continues to delegate to `X509.Certificate.new` inside the builder; classical→PQC uses the hand-rolled ASN.1 path. PQC issuer paths remain stubbed for Phase 3.

**Tech Stack:** Elixir 1.18, Erlang/OTP 25, `:public_key` (classical signing), `pki_crypto`'s existing signer protocol (PQC), ExUnit.

---

## Prerequisites (from Phase 1)

- `PkiCrypto.AlgorithmRegistry.by_id/1` and `by_oid/1` — look up algorithm metadata (family, OIDs).
- `PkiCrypto.Registry.get/1` — returns algorithm struct for sign/verify dispatch via the `PkiCrypto.Algorithm` protocol.
- Validation signer modules (`PkiValidation.Crypto.Signer.MlDsa44` etc.) — not used directly in Phase 2, but the placeholder OIDs they encode must match what this phase emits.

## File structure

**Created:**
- `src/pki_crypto/lib/pki_crypto/asn1.ex` — DER primitive encoder + parser. Pure data, no I/O.
- `src/pki_crypto/lib/pki_crypto/csr.ex` — PKCS#10 parse/verify/generate.
- `src/pki_crypto/lib/pki_crypto/x509_builder.ex` — TBS cert construction and signing.
- `src/pki_crypto/test/pki_crypto/asn1_test.exs`
- `src/pki_crypto/test/pki_crypto/csr_test.exs`
- `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`
- `src/pki_crypto/test/pki_crypto/integration/cross_algo_signing_test.exs`

**Modified:**
- `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex` — rewire the classical-issuer branch through `PkiCrypto.X509Builder`. Leave `do_sign_ml_dsa` and `do_sign_kaz` (PQC issuer) paths in place for Phase 3.

**Out of scope for Phase 2:**
- Retiring the JSON-wrapper cert format (Phase 3).
- Rewiring `PkiCaEngine.CeremonyOrchestrator` to produce PKCS#10 CSRs via `PkiCrypto.Csr.generate` (Phase 3).
- PQC-issuer path in `X509Builder` (Phase 3).
- OCSP/CRL signing (Phase 4).

---

## Shared reference — ASN.1 shapes used in this plan

### PKCS#10 CertificationRequest (RFC 2986)

```
CertificationRequest ::= SEQUENCE {
  certificationRequestInfo  CertificationRequestInfo,
  signatureAlgorithm        AlgorithmIdentifier,
  signature                 BIT STRING
}

CertificationRequestInfo ::= SEQUENCE {
  version                   INTEGER { v1(0) },
  subject                   Name,
  subjectPKInfo             SubjectPublicKeyInfo,
  attributes                [0] IMPLICIT Attributes
}

SubjectPublicKeyInfo ::= SEQUENCE {
  algorithm                 AlgorithmIdentifier,
  subjectPublicKey          BIT STRING
}

Name ::= SEQUENCE OF RelativeDistinguishedName
RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }

AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
```

### TBSCertificate (RFC 5280, X.509 v3)

```
TBSCertificate ::= SEQUENCE {
  version                [0] EXPLICIT INTEGER DEFAULT v1,          -- set to v3 (2)
  serialNumber           CertificateSerialNumber,
  signature              AlgorithmIdentifier,                       -- must match outer sigAlg
  issuer                 Name,
  validity               SEQUENCE { notBefore Time, notAfter Time },
  subject                Name,
  subjectPublicKeyInfo   SubjectPublicKeyInfo,
  issuerUniqueID         [1] IMPLICIT BIT STRING OPTIONAL,          -- omit
  subjectUniqueID        [2] IMPLICIT BIT STRING OPTIONAL,          -- omit
  extensions             [3] EXPLICIT Extensions OPTIONAL
}

Extensions ::= SEQUENCE OF Extension
Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }

Certificate ::= SEQUENCE {
  tbsCertificate      TBSCertificate,
  signatureAlgorithm  AlgorithmIdentifier,
  signatureValue      BIT STRING
}
```

### Extensions emitted by Phase 2

For sub-CA issuance (default path):
- `basicConstraints` (critical) — `CA:TRUE`, pathLenConstraint absent.
- `keyUsage` (critical) — `keyCertSign | cRLSign`.
- `subjectKeyIdentifier` — SHA-1 of the subject's SPKI.
- `authorityKeyIdentifier` — keyIdentifier = SHA-1 of issuer's SPKI.

For leaf (future Phase 3 default):
- `basicConstraints` (critical) — `CA:FALSE`.
- `keyUsage` (critical) — `digitalSignature | keyEncipherment`.
- `subjectKeyIdentifier`, `authorityKeyIdentifier`.

Phase 2 implements the CA variant. Leaf extensions are added in Phase 3 when the leaf path is wired.

---

## Task 1: `PkiCrypto.Asn1` — primitive DER encoders

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/asn1.ex`
- Create: `src/pki_crypto/test/pki_crypto/asn1_test.exs`

- [ ] **Step 1: Write failing tests**

Create `src/pki_crypto/test/pki_crypto/asn1_test.exs`:

```elixir
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
      # sequence of 3 bytes: 30 03 <3 bytes>
      assert <<0x30, 0x03, 0xAA, 0xBB, 0xCC>> = Asn1.sequence([<<0xAA, 0xBB, 0xCC>>])
    end

    test "long form length for >127 byte body" do
      body = :binary.copy(<<0xAA>>, 200)
      # 30 81 C8 <200 bytes>
      assert <<0x30, 0x81, 0xC8, ^body::binary>> = Asn1.sequence([body])
    end

    test "long form length for >255 byte body" do
      body = :binary.copy(<<0xAA>>, 300)
      # 30 82 01 2C <300 bytes>
      assert <<0x30, 0x82, 0x01, 0x2C, ^body::binary>> = Asn1.sequence([body])
    end
  end
end
```

- [ ] **Step 2: Run to verify fails**

```
cd src/pki_crypto && mix test test/pki_crypto/asn1_test.exs
```

Expected: compile error — `PkiCrypto.Asn1` undefined.

- [ ] **Step 3: Create `asn1.ex` encoder side**

Create `src/pki_crypto/lib/pki_crypto/asn1.ex`:

```elixir
defmodule PkiCrypto.Asn1 do
  @moduledoc """
  DER primitive encoder and decoder for X.509/PKCS#10 fields the
  `:public_key` library does not expose directly — specifically for
  emitting structures that carry non-classical algorithm OIDs in
  `subjectPublicKeyInfo` and `signatureAlgorithm`.

  Only the subset of ASN.1 DER needed by X.509 v3 + PKCS#10 is covered:
  INTEGER, OCTET STRING, BIT STRING, OBJECT IDENTIFIER, BOOLEAN, NULL,
  UTCTime, GeneralizedTime, SEQUENCE, SET, and context-tagged wrappers.

  All encoders return DER bytes suitable for concatenation into parent
  structures. The reader side (`read_*`) takes DER bytes and returns
  `{value, rest}` — callers compose the parsers for nested shapes.
  """

  # --- Encoders ---

  @doc "Encode a non-negative integer as DER INTEGER."
  @spec integer(non_neg_integer()) :: binary()
  def integer(n) when is_integer(n) and n >= 0 do
    bytes = :binary.encode_unsigned(n)

    # Prepend 0x00 if high bit is set (DER INTEGER is two's-complement).
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

    content =
      [first_byte | Enum.map(rest, &encode_base128/1)]
      |> Enum.map(fn
        bs when is_list(bs) -> :erlang.list_to_binary(bs)
        b when is_integer(b) -> <<b>>
      end)
      |> IO.iodata_to_binary()

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
    formatted = :io_lib.format("~2..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
                               [yy, dt.month, dt.day, dt.hour, dt.minute, dt.second])
    content = IO.iodata_to_binary(formatted)
    <<0x17, byte_size(content)>> <> content
  end

  @doc "Encode a GeneralizedTime (used for dates ≥ 2050)."
  @spec generalized_time(DateTime.t()) :: binary()
  def generalized_time(%DateTime{} = dt) do
    formatted = :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
                               [dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second])
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

  `:explicit` wraps the existing DER bytes inside the tag (used for X.509 `[0]` version
  and `[3]` extensions). `:implicit` replaces the outer tag.
  """
  @spec tagged(0..30, :explicit | :implicit, binary()) :: binary()
  def tagged(tag, :explicit, content) when tag in 0..30 and is_binary(content) do
    outer_tag = 0xA0 ||| tag
    <<outer_tag>> <> encode_length(byte_size(content)) <> content
  end

  def tagged(tag, :implicit, <<_old_tag, rest::binary>>) when tag in 0..30 do
    outer_tag = 0x80 ||| tag
    # Preserve length+content, swap outer tag
    {_len, body, _} = decode_length(rest)
    <<outer_tag>> <> encode_length(byte_size(body)) <> body
  end

  # --- Length helpers ---

  @doc false
  def encode_length(n) when n < 128, do: <<n>>
  def encode_length(n) when n < 256, do: <<0x81, n>>
  def encode_length(n) when n < 65_536, do: <<0x82, n::16>>
  def encode_length(n) when n < 16_777_216, do: <<0x83, n::24>>

  @doc false
  def decode_length(<<n, rest::binary>>) when n < 128 do
    <<body::binary-size(n), after_body::binary>> = rest
    {n, body, after_body}
  end

  def decode_length(<<0x81, n, rest::binary>>) do
    <<body::binary-size(n), after_body::binary>> = rest
    {n, body, after_body}
  end

  def decode_length(<<0x82, n::16, rest::binary>>) do
    <<body::binary-size(n), after_body::binary>> = rest
    {n, body, after_body}
  end

  def decode_length(<<0x83, n::24, rest::binary>>) do
    <<body::binary-size(n), after_body::binary>> = rest
    {n, body, after_body}
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

  # Bitwise helpers — Elixir auto-imports from Bitwise module
  import Bitwise
end
```

- [ ] **Step 4: Run tests — all pass**

```
cd src/pki_crypto && mix test test/pki_crypto/asn1_test.exs
```

Expected: 13 tests, 13 passed. If a byte mismatch surfaces, verify by comparing against `openssl asn1parse` on known inputs.

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/asn1.ex src/pki_crypto/test/pki_crypto/asn1_test.exs
git commit -m "feat(pki_crypto): Asn1 DER primitive encoders"
```

---

## Task 2: `PkiCrypto.Asn1` — primitive DER parsers

**Files:**
- Modify: `src/pki_crypto/lib/pki_crypto/asn1.ex`
- Modify: `src/pki_crypto/test/pki_crypto/asn1_test.exs`

- [ ] **Step 1: Write failing tests**

Append to `src/pki_crypto/test/pki_crypto/asn1_test.exs`, inside the defmodule:

```elixir
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
      # SEQUENCE { INTEGER 5, OCTET STRING "abc" }
      body = <<0x02, 0x01, 0x05>> <> <<0x04, 0x03, "abc">>
      assert [<<0x02, 0x01, 0x05>>, <<0x04, 0x03, "abc">>] = Asn1.read_sequence_items(body)
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
  end
```

- [ ] **Step 2: Run to verify fails**

Expected: 12 new tests fail — readers undefined.

- [ ] **Step 3: Add reader functions**

In `src/pki_crypto/lib/pki_crypto/asn1.ex`, append before the final `import Bitwise`:

```elixir
  # --- Decoders ---

  @doc "Decode DER INTEGER. Returns `{non_neg_integer, rest}`."
  @spec read_integer(binary()) :: {non_neg_integer(), binary()}
  def read_integer(<<0x02, rest::binary>>) do
    {_len, body, after_body} = decode_length(rest)
    {:binary.decode_unsigned(body), after_body}
  end

  @doc "Decode DER OID. Returns `{arcs_tuple, rest}`."
  @spec read_oid(binary()) :: {tuple(), binary()}
  def read_oid(<<0x06, rest::binary>>) do
    {_len, body, after_body} = decode_length(rest)
    <<first, subs::binary>> = body
    a1 = div(first, 40)
    a2 = rem(first, 40)
    {a1, a2}
    tail = decode_subidentifiers(subs, 0, [])
    {List.to_tuple([a1, a2 | tail]), after_body}
  end

  defp decode_subidentifiers(<<>>, _acc, out), do: Enum.reverse(out)
  defp decode_subidentifiers(<<b, rest::binary>>, acc, out) when b >= 0x80 do
    decode_subidentifiers(rest, ((acc <<< 7) ||| (b &&& 0x7F)), out)
  end
  defp decode_subidentifiers(<<b, rest::binary>>, acc, out) do
    decode_subidentifiers(rest, 0, [(acc <<< 7) ||| b | out])
  end

  @doc "Decode DER BIT STRING (assumes unused_bits=0). Returns `{bytes, rest}`."
  @spec read_bit_string(binary()) :: {binary(), binary()}
  def read_bit_string(<<0x03, rest::binary>>) do
    {_len, body, after_body} = decode_length(rest)
    <<0x00, content::binary>> = body
    {content, after_body}
  end

  @doc "Decode DER OCTET STRING. Returns `{bytes, rest}`."
  @spec read_octet_string(binary()) :: {binary(), binary()}
  def read_octet_string(<<0x04, rest::binary>>) do
    {_len, body, after_body} = decode_length(rest)
    {body, after_body}
  end

  @doc "Decode DER SEQUENCE. Returns `{body_bytes, rest}`. Caller re-parses the body."
  @spec read_sequence(binary()) :: {binary(), binary()}
  def read_sequence(<<0x30, rest::binary>>) do
    {_len, body, after_body} = decode_length(rest)
    {body, after_body}
  end

  @doc """
  Split a SEQUENCE body into its constituent DER elements.
  Each element retains its own tag+length prefix.
  """
  @spec read_sequence_items(binary()) :: [binary()]
  def read_sequence_items(<<>>), do: []

  def read_sequence_items(<<tag, rest::binary>>) do
    {len_header_size, len} = peek_length(rest)
    total = 1 + len_header_size + len
    <<item::binary-size(total), more::binary>> = <<tag, rest::binary>>
    [item | read_sequence_items(more)]
  end

  defp peek_length(<<n, _::binary>>) when n < 128, do: {1, n}
  defp peek_length(<<0x81, n, _::binary>>), do: {2, n}
  defp peek_length(<<0x82, n::16, _::binary>>), do: {3, n}
  defp peek_length(<<0x83, n::24, _::binary>>), do: {4, n}
```

- [ ] **Step 4: Run tests — all pass**

Expected: 25 tests, 25 passed (13 from Task 1 + 12 new).

If any round-trip test fails, compare byte-for-byte against the output of `openssl asn1parse -inform der -in <(printf '<bytes>')`.

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/asn1.ex src/pki_crypto/test/pki_crypto/asn1_test.exs
git commit -m "feat(pki_crypto): Asn1 DER primitive parsers"
```

---

## Task 3: `PkiCrypto.Csr` — parse classical PKCS#10

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/csr.ex`
- Create: `src/pki_crypto/test/pki_crypto/csr_test.exs`

- [ ] **Step 1: Write failing test**

Create `src/pki_crypto/test/pki_crypto/csr_test.exs`:

```elixir
defmodule PkiCrypto.CsrTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.Csr

  describe "parse/1 on a classical ECDSA-P256 CSR" do
    setup do
      private_key = X509.PrivateKey.new_ec(:secp256r1)
      csr = X509.CSR.new(private_key, "/CN=Test Subject/O=Acme")
      pem = X509.CSR.to_pem(csr)

      %{pem: pem, private_key: private_key}
    end

    test "extracts subject DN, algorithm, public key, raw TBS, and signature", %{pem: pem} do
      assert {:ok, parsed} = Csr.parse(pem)

      assert parsed.algorithm_id == "ECC-P256"
      assert parsed.subject_dn =~ "CN=Test Subject"
      assert is_binary(parsed.subject_public_key)
      assert is_binary(parsed.raw_tbs)
      assert is_binary(parsed.signature)
    end

    test "raw_tbs matches the DER of CertificationRequestInfo", %{pem: pem} do
      {:ok, parsed} = Csr.parse(pem)
      # raw_tbs must be the exact bytes that were signed. PoP verification depends on this.
      assert byte_size(parsed.raw_tbs) > 0
      assert <<0x30, _rest::binary>> = parsed.raw_tbs
    end
  end

  describe "parse/1 error paths" do
    test "returns error on garbage input" do
      assert {:error, _} = Csr.parse("-----BEGIN CERTIFICATE REQUEST-----\nZ\n-----END CERTIFICATE REQUEST-----\n")
    end

    test "returns error on unknown algorithm OID" do
      # Craft a CSR with a bogus SPKI OID. For this test, use a pre-built fixture or
      # hand-construct a minimal PKCS#10 with an OID that AlgorithmRegistry does not know.
      bogus_oid = PkiCrypto.Asn1.oid({1, 2, 3, 4, 5})
      bogus_alg_id = PkiCrypto.Asn1.sequence([bogus_oid])
      bogus_spki = PkiCrypto.Asn1.sequence([bogus_alg_id, PkiCrypto.Asn1.bit_string(<<0, 0, 0>>)])
      bogus_name = PkiCrypto.Asn1.sequence([])
      bogus_tbs = PkiCrypto.Asn1.sequence([
        PkiCrypto.Asn1.integer(0),
        bogus_name,
        bogus_spki,
        PkiCrypto.Asn1.tagged(0, :explicit, <<>>)
      ])
      bogus_sig_alg = PkiCrypto.Asn1.sequence([bogus_oid])
      bogus_csr_der = PkiCrypto.Asn1.sequence([
        bogus_tbs,
        bogus_sig_alg,
        PkiCrypto.Asn1.bit_string(<<>>)
      ])

      pem = "-----BEGIN CERTIFICATE REQUEST-----\n" <>
            Base.encode64(bogus_csr_der, padding: true) <>
            "\n-----END CERTIFICATE REQUEST-----\n"

      assert {:error, :unknown_algorithm_oid} = Csr.parse(pem)
    end
  end
end
```

- [ ] **Step 2: Run to verify fails**

```
cd src/pki_crypto && mix test test/pki_crypto/csr_test.exs
```

Expected: compile error — `PkiCrypto.Csr` undefined.

- [ ] **Step 3: Create the module**

Create `src/pki_crypto/lib/pki_crypto/csr.ex`:

```elixir
defmodule PkiCrypto.Csr do
  @moduledoc """
  PKCS#10 CertificationRequest (RFC 2986) parse, verify, and generate.
  Supports both classical (RSA/ECDSA) and PQC (ML-DSA, KAZ-SIGN) algorithms
  via `PkiCrypto.AlgorithmRegistry` OID lookup.
  """

  alias PkiCrypto.{Asn1, AlgorithmRegistry}

  @type parsed :: %{
          algorithm_id: String.t(),
          subject_dn: String.t(),
          subject_public_key: binary(),
          raw_tbs: binary(),
          signature: binary()
        }

  @doc """
  Parse a PKCS#10 CSR in PEM form. Returns
  `{:ok, %{algorithm_id, subject_dn, subject_public_key, raw_tbs, signature}}`
  or `{:error, reason}`.

  `raw_tbs` is the exact DER bytes of `CertificationRequestInfo` — these are
  what the subject signed, and must be passed unchanged to `verify_pop/1`.
  """
  @spec parse(binary()) :: {:ok, parsed()} | {:error, atom()}
  def parse(pem) when is_binary(pem) do
    with {:ok, der} <- decode_pem(pem),
         {cri_body, sig_body, _rest} <- unwrap_outer(der),
         {cri_der, _rest_after_cri} <- {reattach_sequence(cri_body), <<>>},
         {:ok, cri} <- parse_cri(cri_body),
         {:ok, algorithm_id} <- resolve_algorithm(cri.spki_oid) do
      {sig_alg_der, sig_and_rest} = slice_element(sig_body)
      {signature, <<>>} = Asn1.read_bit_string(sig_and_rest)
      _ = sig_alg_der

      {:ok,
       %{
         algorithm_id: algorithm_id,
         subject_dn: cri.subject_dn,
         subject_public_key: cri.spki_key,
         raw_tbs: cri_der,
         signature: signature
       }}
    end
  rescue
    _ -> {:error, :malformed_csr}
  catch
    :throw, reason -> {:error, reason}
  end

  # --- Private ---

  defp decode_pem(pem) do
    case :public_key.pem_decode(pem) do
      [{:CertificationRequest, der, _}] -> {:ok, der}
      [] -> {:error, :not_a_csr}
      _ -> {:error, :not_a_csr}
    end
  end

  # Returns {cri_body_bytes, rest_after_cri} where rest holds sigAlg + signature.
  # Also returns the outer CRI DER (tag+length+body) because PoP needs it.
  defp unwrap_outer(der) do
    {outer_body, <<>>} = Asn1.read_sequence(der)
    items = Asn1.read_sequence_items(outer_body)

    case items do
      [cri_der, sig_alg_der, sig_bit_string] ->
        {cri_der, sig_alg_der <> sig_bit_string, <<>>}

      _ ->
        throw(:malformed_csr_structure)
    end
  end

  defp reattach_sequence(<<0x30, _::binary>> = cri_der), do: cri_der

  defp parse_cri(<<0x30, rest::binary>> = _cri_der) do
    {body, <<>>} = Asn1.read_sequence(<<0x30, rest::binary>>)
    [version_der, subject_der, spki_der, _attrs_der] = Asn1.read_sequence_items(body)
    {0, <<>>} = Asn1.read_integer(version_der)

    subject_dn = decode_subject_dn(subject_der)
    {spki_oid, spki_key} = decode_spki(spki_der)

    {:ok, %{subject_dn: subject_dn, spki_oid: spki_oid, spki_key: spki_key}}
  end

  # Very small Name decoder — concatenates the RDN string values as "/type=value".
  # Does not handle every AttributeTypeAndValue encoding; enough for common cases.
  defp decode_subject_dn(<<0x30, _::binary>> = name_der) do
    {name_body, <<>>} = Asn1.read_sequence(name_der)
    rdns = Asn1.read_sequence_items(name_body)
    parts = Enum.flat_map(rdns, &decode_rdn/1)
    "/" <> Enum.join(parts, "/")
  end

  defp decode_rdn(<<0x31, _::binary>> = rdn_der) do
    {body, <<>>} = rdn_read_set(rdn_der)
    atvs = Asn1.read_sequence_items(body)

    Enum.map(atvs, fn atv ->
      {atv_body, <<>>} = Asn1.read_sequence(atv)
      [oid_der, value_der] = Asn1.read_sequence_items(atv_body)
      {oid_tuple, <<>>} = Asn1.read_oid(oid_der)
      key = oid_to_dn_key(oid_tuple)
      value = decode_directory_string(value_der)
      "#{key}=#{value}"
    end)
  end

  defp rdn_read_set(<<0x31, rest::binary>>) do
    {_len, body, after_body} = PkiCrypto.Asn1.decode_length(rest)
    {body, after_body}
  end

  defp oid_to_dn_key({2, 5, 4, 3}), do: "CN"
  defp oid_to_dn_key({2, 5, 4, 6}), do: "C"
  defp oid_to_dn_key({2, 5, 4, 7}), do: "L"
  defp oid_to_dn_key({2, 5, 4, 8}), do: "ST"
  defp oid_to_dn_key({2, 5, 4, 10}), do: "O"
  defp oid_to_dn_key({2, 5, 4, 11}), do: "OU"
  defp oid_to_dn_key(other), do: oid_to_dotted(other)

  defp oid_to_dotted(tuple) do
    tuple |> Tuple.to_list() |> Enum.join(".")
  end

  # Directory string: PrintableString, UTF8String, IA5String, or TeletexString. All carry raw bytes.
  defp decode_directory_string(<<_tag, rest::binary>>) do
    {_len, body, _} = PkiCrypto.Asn1.decode_length(rest)
    body
  end

  defp decode_spki(<<0x30, _::binary>> = spki_der) do
    {body, <<>>} = Asn1.read_sequence(spki_der)
    [alg_id_der, bit_string_der] = Asn1.read_sequence_items(body)
    {alg_body, <<>>} = Asn1.read_sequence(alg_id_der)
    [oid_der | _rest_of_alg] = Asn1.read_sequence_items(alg_body)
    {oid, <<>>} = Asn1.read_oid(oid_der)
    {key, <<>>} = Asn1.read_bit_string(bit_string_der)
    {oid, key}
  end

  defp resolve_algorithm(oid) do
    case AlgorithmRegistry.by_oid(oid) do
      {:ok, %{id: id}} -> {:ok, id}
      :error -> maybe_spki_algo(oid)
    end
  end

  # SPKI public_key_oid may differ from sig_alg_oid (ECDSA case). Fall back to a
  # second lookup on public_key_oid equality.
  defp maybe_spki_algo(oid) do
    entries = ["RSA-2048", "RSA-4096", "ECC-P256", "ECC-P384", "ML-DSA-44", "ML-DSA-65",
               "ML-DSA-87", "KAZ-SIGN-128", "KAZ-SIGN-192", "KAZ-SIGN-256"]

    Enum.find_value(entries, {:error, :unknown_algorithm_oid}, fn id ->
      case AlgorithmRegistry.by_id(id) do
        {:ok, %{public_key_oid: ^oid}} -> {:ok, id}
        _ -> nil
      end
    end)
  end

  # slice_element returns {first_der_element, rest}.
  defp slice_element(<<tag, rest::binary>>) do
    {len, _body, _after} = PkiCrypto.Asn1.decode_length(rest)

    header_size =
      cond do
        len < 128 -> 2
        len < 256 -> 3
        len < 65_536 -> 4
        true -> 5
      end

    total = header_size + len
    <<first::binary-size(total), remainder::binary>> = <<tag, rest::binary>>
    {first, remainder}
  end
end
```

- [ ] **Step 4: Run tests — all pass**

```
cd src/pki_crypto && mix test test/pki_crypto/csr_test.exs
```

Expected: 3 tests, 3 passed.

If the DN decoder doesn't produce the expected substring, verify against the subject you passed to `X509.CSR.new` — ECDSA subjects serialize with UTF-8 strings by default and the test's substring match is lenient.

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/csr.ex src/pki_crypto/test/pki_crypto/csr_test.exs
git commit -m "feat(pki_crypto): Csr.parse/1 for classical PKCS#10"
```

---

## Task 4: `PkiCrypto.Csr.generate/3` — classical + PQC

**Files:**
- Modify: `src/pki_crypto/lib/pki_crypto/csr.ex`
- Modify: `src/pki_crypto/test/pki_crypto/csr_test.exs`

This task adds the generator so Task 5 (verify_pop) and Task 8 (integration) have test fixtures.

- [ ] **Step 1: Write failing tests**

Append to `src/pki_crypto/test/pki_crypto/csr_test.exs`:

```elixir
  describe "generate/3 for classical" do
    test "produces a CSR that parses back to the same algorithm and subject" do
      private_key = X509.PrivateKey.new_ec(:secp256r1)

      {:ok, pem} = Csr.generate("ECC-P256", private_key, "/CN=Classical Gen Test")

      assert {:ok, parsed} = Csr.parse(pem)
      assert parsed.algorithm_id == "ECC-P256"
      assert parsed.subject_dn =~ "CN=Classical Gen Test"
    end
  end

  describe "generate/3 for PQC" do
    test "KAZ-SIGN-192 CSR parses back correctly" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      {:ok, pem} = Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=PQC Sub CA")

      assert {:ok, parsed} = Csr.parse(pem)
      assert parsed.algorithm_id == "KAZ-SIGN-192"
      assert parsed.subject_dn =~ "CN=PQC Sub CA"
      assert parsed.subject_public_key == pub
    end

    test "ML-DSA-44 CSR parses back correctly" do
      algo = PkiCrypto.Registry.get("ML-DSA-44")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      {:ok, pem} = Csr.generate("ML-DSA-44", %{public_key: pub, private_key: priv}, "/CN=ML-DSA Test")

      assert {:ok, parsed} = Csr.parse(pem)
      assert parsed.algorithm_id == "ML-DSA-44"
      assert parsed.subject_public_key == pub
    end
  end
```

- [ ] **Step 2: Run to verify fails**

Expected: 3 tests fail with `Csr.generate/3` undefined.

- [ ] **Step 3: Add `generate/3`**

In `src/pki_crypto/lib/pki_crypto/csr.ex`, add these public functions above the `# --- Private ---` section:

```elixir
  @doc """
  Generate a PKCS#10 CSR for the given algorithm, private key, and subject DN string
  (slash-separated, e.g. `"/CN=Foo/O=Bar"`).

  Classical algorithms delegate to `X509.CSR.new`. PQC algorithms hand-roll the
  PKCS#10 structure and self-sign via the PQC signer module.

  For PQC, the `key` argument must be `%{public_key: binary, private_key: binary}`.
  For classical, it is a `:public_key` private-key record (as returned by
  `X509.PrivateKey.new_ec/1` or `X509.PrivateKey.new_rsa/1`).
  """
  @spec generate(String.t(), term(), String.t()) :: {:ok, binary()} | {:error, term()}
  def generate(algorithm_id, key, subject_dn)

  def generate(algorithm_id, private_key, subject_dn) when algorithm_id in ["ECC-P256", "ECC-P384", "RSA-2048", "RSA-4096"] do
    csr = X509.CSR.new(private_key, subject_dn)
    {:ok, X509.CSR.to_pem(csr)}
  end

  def generate(algorithm_id, %{public_key: pub, private_key: priv}, subject_dn) do
    with {:ok, %{family: family, public_key_oid: pk_oid, sig_alg_oid: sig_oid}} <- AlgorithmRegistry.by_id(algorithm_id),
         true <- family in [:ml_dsa, :kaz_sign, :slh_dsa] do
      # CertificationRequestInfo
      cri_der = build_cri(pk_oid, pub, subject_dn)

      # Self-sign using PQC signer
      algo = PkiCrypto.Registry.get(algorithm_id)
      {:ok, signature} = sign_with_algo(algo, priv, cri_der)

      sig_alg_der = Asn1.sequence([Asn1.oid(sig_oid)])
      csr_der = Asn1.sequence([cri_der, sig_alg_der, Asn1.bit_string(signature)])

      pem = :public_key.pem_encode([{:CertificationRequest, csr_der, :not_encrypted}])
      {:ok, pem}
    else
      :error -> {:error, :unknown_algorithm}
      false -> {:error, :algorithm_not_pqc}
    end
  end

  # Build the CertificationRequestInfo body for a PQC CSR.
  defp build_cri(pk_oid, public_key, subject_dn) do
    version = Asn1.integer(0)
    subject = encode_name(subject_dn)
    spki = Asn1.sequence([
      Asn1.sequence([Asn1.oid(pk_oid)]),
      Asn1.bit_string(public_key)
    ])
    attrs = Asn1.tagged(0, :explicit, <<>>)

    Asn1.sequence([version, subject, spki, attrs])
  end

  # Encode a slash-separated DN string as an X.509 Name. Minimal — supports CN/O/OU/C/ST/L.
  defp encode_name(dn_string) do
    parts =
      dn_string
      |> String.split("/", trim: true)
      |> Enum.map(fn
        part ->
          [key, value] = String.split(part, "=", parts: 2)
          {dn_key_to_oid(key), value}
      end)

    rdns =
      Enum.map(parts, fn {oid, value} ->
        atv = Asn1.sequence([
          Asn1.oid(oid),
          # UTF8String tag = 0x0C
          <<0x0C, byte_size(value)>> <> value
        ])

        Asn1.set([atv])
      end)

    Asn1.sequence(rdns)
  end

  defp dn_key_to_oid("CN"), do: {2, 5, 4, 3}
  defp dn_key_to_oid("C"), do: {2, 5, 4, 6}
  defp dn_key_to_oid("L"), do: {2, 5, 4, 7}
  defp dn_key_to_oid("ST"), do: {2, 5, 4, 8}
  defp dn_key_to_oid("O"), do: {2, 5, 4, 10}
  defp dn_key_to_oid("OU"), do: {2, 5, 4, 11}

  defp sign_with_algo(algo, priv, data) do
    case PkiCrypto.Algorithm.sign(algo, priv, data) do
      {:ok, sig} -> {:ok, sig}
      other -> {:error, other}
    end
  end
```

- [ ] **Step 4: Run tests — all pass**

```
cd src/pki_crypto && mix test test/pki_crypto/csr_test.exs
```

Expected: 6 tests, 6 passed (3 from Task 3 + 3 new).

If the PQC CSR fails to parse back, the most likely issue is the DN encoding or SPKI bit_string wrapping. Compare the output against the classical CSR's SPKI bytes via `openssl asn1parse -inform der`.

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/csr.ex src/pki_crypto/test/pki_crypto/csr_test.exs
git commit -m "feat(pki_crypto): Csr.generate/3 for classical and PQC"
```

---

## Task 5: `PkiCrypto.Csr.verify_pop/1`

**Files:**
- Modify: `src/pki_crypto/lib/pki_crypto/csr.ex`
- Modify: `src/pki_crypto/test/pki_crypto/csr_test.exs`

- [ ] **Step 1: Write failing tests**

Append to `src/pki_crypto/test/pki_crypto/csr_test.exs`:

```elixir
  describe "verify_pop/1" do
    test "accepts a valid classical CSR" do
      private_key = X509.PrivateKey.new_ec(:secp256r1)
      {:ok, pem} = Csr.generate("ECC-P256", private_key, "/CN=PoP Test")
      {:ok, parsed} = Csr.parse(pem)

      assert :ok = Csr.verify_pop(parsed)
    end

    test "accepts a valid KAZ-SIGN-192 CSR" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
      {:ok, pem} = Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=PoP KAZ")
      {:ok, parsed} = Csr.parse(pem)

      assert :ok = Csr.verify_pop(parsed)
    end

    test "accepts a valid ML-DSA-44 CSR" do
      algo = PkiCrypto.Registry.get("ML-DSA-44")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
      {:ok, pem} = Csr.generate("ML-DSA-44", %{public_key: pub, private_key: priv}, "/CN=PoP ML-DSA")
      {:ok, parsed} = Csr.parse(pem)

      assert :ok = Csr.verify_pop(parsed)
    end

    test "rejects a CSR whose signature has been tampered with" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
      {:ok, pem} = Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=Tamper")
      {:ok, parsed} = Csr.parse(pem)

      tampered = %{parsed | signature: :crypto.strong_rand_bytes(byte_size(parsed.signature))}

      assert {:error, :invalid_signature} = Csr.verify_pop(tampered)
    end
  end
```

- [ ] **Step 2: Run to verify fails**

Expected: 4 tests fail.

- [ ] **Step 3: Add `verify_pop/1`**

In `src/pki_crypto/lib/pki_crypto/csr.ex`, above `# --- Private ---`:

```elixir
  @doc """
  Verify the Proof-of-Possession signature on a parsed CSR.
  Returns `:ok` on valid, `{:error, :invalid_signature}` otherwise.
  """
  @spec verify_pop(parsed()) :: :ok | {:error, :invalid_signature}
  def verify_pop(%{algorithm_id: algorithm_id, subject_public_key: pub, raw_tbs: tbs, signature: sig}) do
    algo = PkiCrypto.Registry.get(algorithm_id)

    case PkiCrypto.Algorithm.verify(algo, pub, sig, tbs) do
      :ok -> :ok
      _ -> {:error, :invalid_signature}
    end
  end
```

The `PkiCrypto.Algorithm.verify/4` implementations in `pki_crypto/lib/pki_crypto/signing/*.ex` already dispatch per algorithm family. Classical uses `:public_key.verify`, PQC uses the NIF.

- [ ] **Step 4: Run tests — all pass**

Expected: 10 tests, 10 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/csr.ex src/pki_crypto/test/pki_crypto/csr_test.exs
git commit -m "feat(pki_crypto): Csr.verify_pop/1 (classical + PQC)"
```

---

## Task 6: `PkiCrypto.X509Builder.build_tbs_cert/5`

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/x509_builder.ex`
- Create: `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`

- [ ] **Step 1: Write failing test**

Create `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`:

```elixir
defmodule PkiCrypto.X509BuilderTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.{Csr, X509Builder}

  describe "build_tbs_cert/5 — classical issuer, PQC subject" do
    setup do
      # Issuer: ECDSA-P384 (root)
      issuer_priv = X509.PrivateKey.new_ec(:secp384r1)
      issuer_cert = X509.Certificate.self_signed(issuer_priv, "/CN=Root")

      # Subject: KAZ-SIGN-192 sub-CA CSR
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
      {:ok, csr_pem} = Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=Sub CA")
      {:ok, csr} = Csr.parse(csr_pem)

      %{issuer_priv: issuer_priv, issuer_cert: issuer_cert, csr: csr, subject_pub: pub}
    end

    test "produces DER whose outer structure is SEQUENCE", ctx do
      {:ok, tbs_der, _sig_alg_oid} =
        X509Builder.build_tbs_cert(ctx.csr, %{
          cert_der: X509.Certificate.to_der(ctx.issuer_cert),
          algorithm_id: "ECC-P384"
        }, "/CN=Sub CA", 365, 12345)

      assert <<0x30, _rest::binary>> = tbs_der
    end

    test "signature_algorithm_oid is the ISSUER's OID", ctx do
      {:ok, _tbs, sig_alg_oid} =
        X509Builder.build_tbs_cert(ctx.csr, %{
          cert_der: X509.Certificate.to_der(ctx.issuer_cert),
          algorithm_id: "ECC-P384"
        }, "/CN=Sub CA", 365, 12345)

      assert sig_alg_oid == {1, 2, 840, 10045, 4, 3, 3}
    end

    test "embeds subject's PQC public key in SPKI", ctx do
      {:ok, tbs_der, _} =
        X509Builder.build_tbs_cert(ctx.csr, %{
          cert_der: X509.Certificate.to_der(ctx.issuer_cert),
          algorithm_id: "ECC-P384"
        }, "/CN=Sub CA", 365, 12345)

      # The subject's public key bytes must appear verbatim somewhere in the TBS DER
      assert :binary.match(tbs_der, ctx.subject_pub) != :nomatch
    end
  end
end
```

- [ ] **Step 2: Run to verify fails**

Expected: compile error.

- [ ] **Step 3: Create `x509_builder.ex`**

Create `src/pki_crypto/lib/pki_crypto/x509_builder.ex`:

```elixir
defmodule PkiCrypto.X509Builder do
  @moduledoc """
  X.509 v3 TBSCertificate construction and signing with cross-algorithm support.

  Phase 2: classical issuer (RSA/ECDSA) signs a subject with any algorithm
  (classical or PQC). PQC issuer paths are stubbed until Phase 3.
  """

  alias PkiCrypto.{Asn1, AlgorithmRegistry}

  @type issuer_ref :: %{cert_der: binary(), algorithm_id: String.t()}

  @doc """
  Build a TBSCertificate DER from a parsed CSR, issuer reference, target subject DN,
  validity in days, and serial number (integer).

  Returns `{:ok, tbs_der, signature_algorithm_oid}`.
  """
  @spec build_tbs_cert(PkiCrypto.Csr.parsed(), issuer_ref(), String.t(), pos_integer(), pos_integer()) ::
          {:ok, binary(), tuple()} | {:error, term()}
  def build_tbs_cert(csr, issuer_ref, subject_dn, validity_days, serial) do
    with {:ok, subject_meta} <- AlgorithmRegistry.by_id(csr.algorithm_id),
         {:ok, issuer_meta} <- AlgorithmRegistry.by_id(issuer_ref.algorithm_id) do
      version = Asn1.tagged(0, :explicit, Asn1.integer(2))
      serial_der = Asn1.integer(serial)
      sig_alg = Asn1.sequence([Asn1.oid(issuer_meta.sig_alg_oid)])
      issuer_name = extract_subject_name(issuer_ref.cert_der)

      now = DateTime.utc_now() |> DateTime.truncate(:second)
      not_after = DateTime.add(now, validity_days * 86400, :second)
      validity = Asn1.sequence([encode_time(now), encode_time(not_after)])

      subject_name = encode_name_from_dn_string(subject_dn)

      spki = Asn1.sequence([
        Asn1.sequence([Asn1.oid(subject_meta.public_key_oid)]),
        Asn1.bit_string(csr.subject_public_key)
      ])

      extensions = build_sub_ca_extensions(csr.subject_public_key, issuer_ref.cert_der)

      tbs = Asn1.sequence([
        version,
        serial_der,
        sig_alg,
        issuer_name,
        validity,
        subject_name,
        spki,
        extensions
      ])

      {:ok, tbs, issuer_meta.sig_alg_oid}
    end
  end

  # --- Extensions ---

  defp build_sub_ca_extensions(subject_pub, issuer_cert_der) do
    bc = make_extension({2, 5, 29, 19}, true, Asn1.sequence([Asn1.boolean(true)]))
    ku = make_extension({2, 5, 29, 15}, true, key_usage_keycertsign_crlsign())
    ski = make_extension({2, 5, 29, 14}, false, Asn1.octet_string(sha1(subject_pub)))
    aki = make_extension({2, 5, 29, 35}, false, aki_body(issuer_cert_der))

    ext_seq = Asn1.sequence([bc, ku, ski, aki])
    Asn1.tagged(3, :explicit, ext_seq)
  end

  defp make_extension(oid, critical, value_der) do
    items = if critical do
      [Asn1.oid(oid), Asn1.boolean(true), Asn1.octet_string(value_der)]
    else
      [Asn1.oid(oid), Asn1.octet_string(value_der)]
    end

    Asn1.sequence(items)
  end

  # keyCertSign (bit 5) + cRLSign (bit 6) — BIT STRING "00000011" (mask 0x06)
  defp key_usage_keycertsign_crlsign do
    # BIT STRING with 1 unused bit (the 6-bit value 000001 1 -> 0x06 occupies bits 5+6,
    # unused_bits = 1 because total bit length is 7).
    content = <<0x01, 0x06>>
    <<0x03, byte_size(content)>> <> content
  end

  defp aki_body(issuer_cert_der) do
    # AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
    issuer_spki_bytes = extract_spki_bit_string_content(issuer_cert_der)
    ki = sha1(issuer_spki_bytes)

    # [0] IMPLICIT OCTET STRING content — tag 0x80, length, bytes
    ki_tagged = <<0x80, byte_size(ki)>> <> ki
    Asn1.sequence([ki_tagged])
  end

  # --- Helpers reused from classical cert path ---

  defp extract_subject_name(cert_der) do
    # Certificate ::= SEQUENCE { TBSCertificate, sigAlg, sig }
    {body, <<>>} = Asn1.read_sequence(cert_der)
    [tbs_der | _] = Asn1.read_sequence_items(body)
    {tbs_body, <<>>} = Asn1.read_sequence(tbs_der)
    # TBS items: version [0], serial, sigAlg, issuer, validity, subject, SPKI, [extensions]
    items = Asn1.read_sequence_items(tbs_body)
    # Skip version if present (tag 0xA0)
    items = drop_optional_version(items)
    [_serial, _sig_alg, _issuer, _validity, subject | _rest] = items
    subject
  end

  defp extract_spki_bit_string_content(cert_der) do
    {body, <<>>} = Asn1.read_sequence(cert_der)
    [tbs_der | _] = Asn1.read_sequence_items(body)
    {tbs_body, <<>>} = Asn1.read_sequence(tbs_der)
    items = Asn1.read_sequence_items(tbs_body) |> drop_optional_version()
    [_serial, _sig_alg, _issuer, _validity, _subject, spki_der | _] = items
    {spki_body, <<>>} = Asn1.read_sequence(spki_der)
    [_alg_id, bit_string_der] = Asn1.read_sequence_items(spki_body)
    {content, <<>>} = Asn1.read_bit_string(bit_string_der)
    content
  end

  defp drop_optional_version([<<0xA0, _::binary>> | rest]), do: rest
  defp drop_optional_version(items), do: items

  defp encode_time(%DateTime{year: y} = dt) when y >= 1950 and y < 2050, do: Asn1.utc_time(dt)
  defp encode_time(dt), do: Asn1.generalized_time(dt)

  defp encode_name_from_dn_string(dn_string) do
    parts =
      dn_string
      |> String.split("/", trim: true)
      |> Enum.map(fn part ->
        [k, v] = String.split(part, "=", parts: 2)
        {dn_key_to_oid(k), v}
      end)

    rdns = Enum.map(parts, fn {oid, value} ->
      atv = Asn1.sequence([
        Asn1.oid(oid),
        <<0x0C, byte_size(value)>> <> value
      ])
      Asn1.set([atv])
    end)

    Asn1.sequence(rdns)
  end

  defp dn_key_to_oid("CN"), do: {2, 5, 4, 3}
  defp dn_key_to_oid("C"), do: {2, 5, 4, 6}
  defp dn_key_to_oid("L"), do: {2, 5, 4, 7}
  defp dn_key_to_oid("ST"), do: {2, 5, 4, 8}
  defp dn_key_to_oid("O"), do: {2, 5, 4, 10}
  defp dn_key_to_oid("OU"), do: {2, 5, 4, 11}

  defp sha1(bytes), do: :crypto.hash(:sha, bytes)
end
```

- [ ] **Step 4: Run tests — all pass**

```
cd src/pki_crypto && mix test test/pki_crypto/x509_builder_test.exs
```

Expected: 3 tests, 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/x509_builder.ex src/pki_crypto/test/pki_crypto/x509_builder_test.exs
git commit -m "feat(pki_crypto): X509Builder.build_tbs_cert/5"
```

---

## Task 7: `PkiCrypto.X509Builder.sign_tbs/3` (classical issuer)

**Files:**
- Modify: `src/pki_crypto/lib/pki_crypto/x509_builder.ex`
- Modify: `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`

- [ ] **Step 1: Write failing test**

Append to `src/pki_crypto/test/pki_crypto/x509_builder_test.exs`:

```elixir
  describe "sign_tbs/3 — classical issuer" do
    test "ECDSA-P384 signs a TBS and the resulting cert parses as X.509" do
      issuer_priv = X509.PrivateKey.new_ec(:secp384r1)
      issuer_cert = X509.Certificate.self_signed(issuer_priv, "/CN=Root")

      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
      {:ok, csr_pem} = PkiCrypto.Csr.generate("KAZ-SIGN-192", %{public_key: pub, private_key: priv}, "/CN=Sub CA")
      {:ok, csr} = PkiCrypto.Csr.parse(csr_pem)

      {:ok, tbs, _} = X509Builder.build_tbs_cert(csr, %{
        cert_der: X509.Certificate.to_der(issuer_cert),
        algorithm_id: "ECC-P384"
      }, "/CN=Sub CA", 365, 12345)

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ECC-P384", issuer_priv)

      # Outer SEQUENCE
      assert <<0x30, _::binary>> = cert_der

      # Parse back to confirm structure
      {outer_body, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, sig_alg, sig_bit_string] = PkiCrypto.Asn1.read_sequence_items(outer_body)

      assert tbs_back == tbs
      assert <<0x30, _::binary>> = sig_alg
      assert <<0x03, _::binary>> = sig_bit_string
    end
  end
```

- [ ] **Step 2: Run to verify fails**

Expected: 1 test fails — `sign_tbs/3` undefined.

- [ ] **Step 3: Add `sign_tbs/3`**

In `src/pki_crypto/lib/pki_crypto/x509_builder.ex`, add:

```elixir
  @doc """
  Sign a TBS DER with the issuer's private key in the given algorithm.
  Wraps `(tbs, sig_alg, signature)` into a final X.509 Certificate DER.

  Classical issuers use `:public_key.sign/3` with the appropriate hash. PQC issuers
  will be implemented in Phase 3.
  """
  @spec sign_tbs(binary(), String.t(), term()) :: {:ok, binary()} | {:error, term()}
  def sign_tbs(tbs_der, issuer_algorithm_id, issuer_private_key) do
    case AlgorithmRegistry.by_id(issuer_algorithm_id) do
      {:ok, %{family: :ecdsa} = meta} ->
        hash = ecdsa_hash_for(issuer_algorithm_id)
        signature = :public_key.sign(tbs_der, hash, issuer_private_key)
        {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}

      {:ok, %{family: :rsa} = meta} ->
        signature = :public_key.sign(tbs_der, :sha256, issuer_private_key)
        {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}

      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        {:error, {:pqc_issuer_not_yet_supported, family}}

      :error ->
        {:error, :unknown_issuer_algorithm}
    end
  end

  defp ecdsa_hash_for("ECC-P256"), do: :sha256
  defp ecdsa_hash_for("ECC-P384"), do: :sha384

  defp wrap_cert(tbs_der, sig_alg_oid, signature) do
    sig_alg = Asn1.sequence([Asn1.oid(sig_alg_oid)])
    Asn1.sequence([tbs_der, sig_alg, Asn1.bit_string(signature)])
  end
```

- [ ] **Step 4: Run tests — all pass**

Expected: 4 tests, 4 passed (3 from Task 6 + 1 new).

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/x509_builder.ex src/pki_crypto/test/pki_crypto/x509_builder_test.exs
git commit -m "feat(pki_crypto): X509Builder.sign_tbs/3 for classical issuers"
```

---

## Task 8: Integration — ECDSA root signs KAZ-SIGN sub-CA, chain verifies

**Files:**
- Create: `src/pki_crypto/test/pki_crypto/integration/cross_algo_signing_test.exs`

- [ ] **Step 1: Write the integration test**

Create `src/pki_crypto/test/pki_crypto/integration/cross_algo_signing_test.exs`:

```elixir
defmodule PkiCrypto.Integration.CrossAlgoSigningTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.{Csr, X509Builder}

  describe "ECDSA-P384 root issuing a KAZ-SIGN-192 sub-CA" do
    test "full flow: generate CSR, root signs, cert parses, subject key embedded" do
      # 1. Build an ECDSA-P384 root CA
      root_priv = X509.PrivateKey.new_ec(:secp384r1)
      root_cert = X509.Certificate.self_signed(root_priv, "/CN=ECDSA Root CA")

      # 2. Generate a KAZ-SIGN-192 sub-CA keypair
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: sub_pub, private_key: sub_priv}} = PkiCrypto.Algorithm.generate_keypair(algo)

      # 3. Sub-CA builds a PKCS#10 CSR, self-signed with KAZ-SIGN-192
      {:ok, csr_pem} = Csr.generate("KAZ-SIGN-192", %{public_key: sub_pub, private_key: sub_priv}, "/CN=KAZ-SIGN Sub CA")

      # 4. Parse + verify the CSR's PoP
      {:ok, parsed} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(parsed)
      assert parsed.algorithm_id == "KAZ-SIGN-192"

      # 5. Root builds a TBS cert and signs with ECDSA-P384
      {:ok, tbs, sig_oid} = X509Builder.build_tbs_cert(parsed, %{
        cert_der: X509.Certificate.to_der(root_cert),
        algorithm_id: "ECC-P384"
      }, "/CN=KAZ-SIGN Sub CA", 1825, 1001)

      assert sig_oid == {1, 2, 840, 10045, 4, 3, 3}

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ECC-P384", root_priv)

      # 6. Parse the emitted cert — structure must be RFC 5280
      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      assert tbs_back == tbs

      {alg_body, <<>>} = PkiCrypto.Asn1.read_sequence(sig_alg)
      [alg_oid_der] = PkiCrypto.Asn1.read_sequence_items(alg_body)
      {oid, <<>>} = PkiCrypto.Asn1.read_oid(alg_oid_der)
      assert oid == {1, 2, 840, 10045, 4, 3, 3}

      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)
      assert is_binary(signature) and byte_size(signature) > 0

      # 7. Verify the root's signature over TBS using :public_key
      pub_from_cert = X509.Certificate.public_key(root_cert)
      assert :public_key.verify(tbs, :sha384, signature, pub_from_cert)

      # 8. Subject key inside the new cert matches the sub-CA's public key
      assert :binary.match(cert_der, sub_pub) != :nomatch
    end
  end

  describe "regression — ECDSA root issuing an ECDSA-P256 leaf (classical-to-classical)" do
    test "existing classical flow still works via the new orchestrator" do
      root_priv = X509.PrivateKey.new_ec(:secp384r1)
      root_cert = X509.Certificate.self_signed(root_priv, "/CN=Root")

      leaf_priv = X509.PrivateKey.new_ec(:secp256r1)
      {:ok, csr_pem} = Csr.generate("ECC-P256", leaf_priv, "/CN=Leaf")
      {:ok, parsed} = Csr.parse(csr_pem)
      assert :ok = Csr.verify_pop(parsed)

      {:ok, tbs, _} = X509Builder.build_tbs_cert(parsed, %{
        cert_der: X509.Certificate.to_der(root_cert),
        algorithm_id: "ECC-P384"
      }, "/CN=Leaf", 365, 2001)

      {:ok, cert_der} = X509Builder.sign_tbs(tbs, "ECC-P384", root_priv)

      {outer, <<>>} = PkiCrypto.Asn1.read_sequence(cert_der)
      [tbs_back, _sig_alg, sig_bits] = PkiCrypto.Asn1.read_sequence_items(outer)
      {signature, <<>>} = PkiCrypto.Asn1.read_bit_string(sig_bits)

      pub_from_cert = X509.Certificate.public_key(root_cert)
      assert :public_key.verify(tbs_back, :sha384, signature, pub_from_cert)
    end
  end
end
```

- [ ] **Step 2: Run tests**

```
cd src/pki_crypto && mix test test/pki_crypto/integration/cross_algo_signing_test.exs
```

Expected: 2 tests, 2 passed. If either fails at a specific step, the failure pinpoints which primitive has a bug — fix at the source (Asn1 / Csr / X509Builder), not in this test.

- [ ] **Step 3: Commit**

```bash
git add src/pki_crypto/test/pki_crypto/integration/cross_algo_signing_test.exs
git commit -m "test(pki_crypto): integration — ECDSA root signs KAZ-SIGN sub-CA"
```

---

## Task 9: Rewire `PkiCaEngine.CertificateSigning` — classical-issuer path through orchestrator

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`

The goal: route `do_sign_with_issuer/6` (the existing classical path) through `PkiCrypto.X509Builder`. PQC-issuer branches (`do_sign_kaz`, `do_sign_ml_dsa`) stay untouched until Phase 3.

- [ ] **Step 1: Read current classical path**

Open `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex`. Locate `do_sign_with_issuer/6` and `do_sign_with_issuer/6` (there are two — the second takes the decoded public key). Confirm the shape of the call site in `do_sign/6`.

- [ ] **Step 2: Modify `do_sign_with_issuer/6` to call through the new orchestrator**

Replace the body of the outer `do_sign_with_issuer/6` with a delegation to `PkiCrypto.X509Builder`:

```elixir
  defp do_sign_with_issuer(issuer_key, issuer_cert, csr_pem, subject_dn, validity_days, serial) do
    issuer_cert_der = X509.Certificate.to_der(issuer_cert)
    issuer_alg_id = issuer_algorithm_id(issuer_cert)
    serial_int = hex_serial_to_integer(serial)

    with {:ok, csr} <- PkiCrypto.Csr.parse(csr_pem),
         :ok <- PkiCrypto.Csr.verify_pop(csr),
         {:ok, tbs, _} <-
           PkiCrypto.X509Builder.build_tbs_cert(csr,
             %{cert_der: issuer_cert_der, algorithm_id: issuer_alg_id},
             subject_dn,
             validity_days,
             serial_int
           ),
         {:ok, cert_der} <- PkiCrypto.X509Builder.sign_tbs(tbs, issuer_alg_id, issuer_key) do
      cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
      {:ok, cert_der, cert_pem}
    else
      {:error, reason} ->
        Logger.error("Certificate signing failed via X509Builder: #{inspect(reason)}")
        {:error, {:signing_failed, reason}}
    end
  end

  defp issuer_algorithm_id(issuer_cert) do
    # Map from :public_key signature algorithm to our algorithm_id strings.
    case X509.Certificate.extension(issuer_cert, :subject_public_key_info) do
      nil -> raise "issuer cert has no SPKI"
      _ -> :ok
    end

    case issuer_cert |> X509.Certificate.public_key() |> elem(0) do
      :RSAPublicKey -> "RSA-4096"
      {:ECPoint, _} -> ec_algo_for(issuer_cert)
    end
  end

  defp ec_algo_for(issuer_cert) do
    # Read the named curve OID from the SPKI algorithm parameters.
    # secp256r1 = {1,2,840,10045,3,1,7}, secp384r1 = {1,3,132,0,34}
    case X509.Certificate.public_key(issuer_cert) do
      {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}} -> "ECC-P256"
      {{:ECPoint, _}, {:namedCurve, {1, 3, 132, 0, 34}}} -> "ECC-P384"
      _ -> raise "unsupported issuer curve"
    end
  end
```

Remove the inner `do_sign_with_issuer/6` (the one accepting `public_key`) and its `extract_public_key_from_csr/1` / `do_sign_with_issuer/6` call — they are now dead code because the new orchestrator handles SPKI extraction inside `X509Builder`. Leave the `do_sign_kaz` and `do_sign_ml_dsa` branches untouched.

- [ ] **Step 3: Run existing CA engine tests**

```
cd src/pki_ca_engine && mix test
```

Expected: tests that exercise classical root → classical leaf issuance still pass. Any failures pinpoint a discrepancy between the old and new code paths — investigate and fix.

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex
git commit -m "refactor(pki_ca_engine): route classical issuer path through PkiCrypto.X509Builder"
```

---

## Task 10: Umbrella regression

- [ ] **Step 1: Run each affected app's full test suite**

```
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_crypto && mix test
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_ca_engine && mix test
cd /Users/amirrudinyahaya/Workspace/pki/src/pki_validation && mix test
```

Expected: all tests pass. No NEW failures vs `main`. The 3 pre-existing `pki_crypto` failures documented in Phase 1 are acceptable carry-over.

- [ ] **Step 2: Umbrella compile check**

```
cd /Users/amirrudinyahaya/Workspace/pki && mix compile 2>&1 | tail -20
```

Expected: clean compile; warnings are pre-existing (no new ones from Phase 2 modules).

- [ ] **Step 3: No separate commit — verification only**

If failures surfaced, fix and re-run before proceeding to VPS smoke.

---

## Task 11: VPS smoke test (user-driven)

After merge to main:

- [ ] **Step 1: Redeploy**

```bash
# local
git push

# VPS
cd ~/pki && git pull
set -a; source <(sudo cat /opt/pki/.env); set +a
sudo rm -rf _build/prod/rel
bash deploy/build.sh 2>&1 | tail -5
sudo bash deploy/deploy.sh 2>&1 | tail -15
sleep 15
sudo systemctl is-active pki-engines pki-portals pki-audit
```

Expected: all three services `active`.

- [ ] **Step 2: Exercise the cross-algo signing path in the running release**

```bash
sudo -u pki bash -c "set -a; source /opt/pki/.env; set +a; /opt/pki/releases/portals/bin/pki_portals eval '
  alias PkiCrypto.{Csr, X509Builder}

  # ECDSA-P384 root
  root_priv = X509.PrivateKey.new_ec(:secp384r1)
  root_cert = X509.Certificate.self_signed(root_priv, \"/CN=VPS Smoke Root\")

  # KAZ-SIGN-192 sub-CA CSR
  algo = PkiCrypto.Registry.get(\"KAZ-SIGN-192\")
  {:ok, %{public_key: pub, private_key: priv}} = PkiCrypto.Algorithm.generate_keypair(algo)
  {:ok, pem} = Csr.generate(\"KAZ-SIGN-192\", %{public_key: pub, private_key: priv}, \"/CN=Smoke Sub CA\")
  {:ok, parsed} = Csr.parse(pem)
  :ok = Csr.verify_pop(parsed)

  # Root signs
  {:ok, tbs, _} = X509Builder.build_tbs_cert(parsed, %{
    cert_der: X509.Certificate.to_der(root_cert),
    algorithm_id: \"ECC-P384\"
  }, \"/CN=Smoke Sub CA\", 365, 99)

  {:ok, cert_der} = X509Builder.sign_tbs(tbs, \"ECC-P384\", root_priv)

  IO.puts(\"phase2_smoke=\" <> to_string(byte_size(cert_der)) <> \" bytes\")
'"
```

Expected output line: `phase2_smoke=<N> bytes` where N is several hundred. Success = no crash, non-empty cert_der.

- [ ] **Step 3: Definition of done**

Phase 2 is complete when:

- `PkiCrypto.Asn1`, `PkiCrypto.Csr`, `PkiCrypto.X509Builder` exist, compile, and pass their unit tests.
- Integration test produces a valid cross-algo cert whose structure round-trips.
- `PkiCaEngine.CertificateSigning` classical-issuer path routes through the new orchestrator; classical CA regression tests still pass.
- VPS smoke test emits a non-empty cert byte count without crashing.
- PQC-issuer branches (`do_sign_kaz`, `do_sign_ml_dsa`) remain in place for Phase 3; no existing ceremony behaviour regresses.

---

## Out-of-scope reminders

- **Retiring JSON-wrapper cert format** — Phase 3.
- **PQC issuer signing classical subject** — Phase 3.
- **Cross-family PQC** (ML-DSA root signing KAZ-SIGN sub) — Phase 3.
- **Rewiring `CeremonyOrchestrator` to use `Csr.generate` during ceremony** — Phase 3. The orchestrator continues to emit JSON-wrapped pseudo-CSRs until then; Phase 2's `Csr.generate` is used only by test fixtures and the future Phase 3 ceremony wiring.
- **OCSP/CRL PQC signing** — Phase 4.

## Exit signal

When all checkboxes above are ticked and the VPS smoke emits `phase2_smoke=<N>` with N > 0, Phase 2 is done. Phase 3 plan follows.
