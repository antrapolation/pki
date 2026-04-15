# Phase 1 — Algorithm Registry + PQC Validation Signers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a single OID-aware algorithm registry under `pki_crypto`, and add PQC (ML-DSA, KAZ-SIGN) signer modules to `pki_validation` so OCSP/CRL signing works in PQC the moment a PQC issuer key is loaded. No cert-emission code changes — this is pure plumbing so Phases 2–4 have a clean foundation.

**Architecture:** Extend `pki_crypto` with `PkiCrypto.AlgorithmRegistry` — a static metadata module mapping `algorithm_id ↔ OID ↔ signer_module ↔ sig_alg_oid`, with OID overrides via `Application.get_env(:pki_crypto, :oid_overrides, %{})`. Add six new `PkiValidation.Crypto.Signer.*` modules (three ML-DSA, three KAZ-SIGN) that conform to the existing `PkiValidation.Crypto.Signer` behaviour and delegate signing to the NIFs already wired through `pki_crypto`. Register them in the validation `Registry` and extend `SigningKeyConfig.@valid_algorithms`.

**Tech Stack:** Elixir 1.18, Erlang/OTP 25, ExUnit, `pki_oqs_nif` (ML-DSA via liboqs), `kaz_sign` NIF.

---

## File structure

**Created files:**
- `src/pki_crypto/lib/pki_crypto/algorithm_registry.ex` — OID-aware metadata registry.
- `src/pki_crypto/test/pki_crypto/algorithm_registry_test.exs`
- `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_44.ex`
- `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_65.ex`
- `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_87.ex`
- `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_128.ex`
- `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_192.ex`
- `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_256.ex`
- `src/pki_validation/test/pki_validation/crypto/signer/ml_dsa_test.exs` (one file covering all three ML-DSA variants)
- `src/pki_validation/test/pki_validation/crypto/signer/kaz_sign_test.exs` (one file covering all three KAZ-SIGN variants)

**Modified files:**
- `src/pki_validation/lib/pki_validation/crypto/signer/registry.ex` — add six PQC entries.
- `src/pki_validation/lib/pki_validation/schema/signing_key_config.ex` — extend `@valid_algorithms`.
- `src/pki_validation/config/test.exs` — add `:pki_crypto, :oid_overrides` default empty map (only if test env needs to exercise overrides).

**Out of scope for Phase 1:** CSR parsing, X.509 emission, `CertificateSigning` changes, `SigningKeyStore` changes beyond loading new algorithm strings — those are Phase 2+.

---

## Conventions and shared code

### OID constants used throughout this plan

| Algorithm ID string | OID | Source |
|---|---|---|
| `"RSA-2048"` / `"RSA-4096"` | `1.2.840.113549.1.1.11` (`sha256WithRSAEncryption`) | RFC 8017 |
| `"ECC-P256"` | `1.2.840.10045.4.3.2` (`ecdsa-with-SHA256`) | RFC 5758 |
| `"ECC-P384"` | `1.2.840.10045.4.3.3` (`ecdsa-with-SHA384`) | RFC 5758 |
| `"ML-DSA-44"` | `2.16.840.1.101.3.4.3.17` | NIST FIPS 204 |
| `"ML-DSA-65"` | `2.16.840.1.101.3.4.3.18` | NIST FIPS 204 |
| `"ML-DSA-87"` | `2.16.840.1.101.3.4.3.19` | NIST FIPS 204 |
| `"KAZ-SIGN-128"` | `1.3.6.1.4.1.99999.1.1.1` | Antrapol PEN **placeholder** — replace before production |
| `"KAZ-SIGN-192"` | `1.3.6.1.4.1.99999.1.1.2` | Antrapol PEN **placeholder** |
| `"KAZ-SIGN-256"` | `1.3.6.1.4.1.99999.1.1.3` | Antrapol PEN **placeholder** |

The `99999` PEN is a placeholder. It MUST be replaced with the real Antrapol IANA PEN before production release. The override mechanism (see Task 2) makes this a single-config-line swap.

### Public key OIDs (for SubjectPublicKeyInfo) — used in Phase 2 but noted here

ML-DSA and KAZ-SIGN use the same OID for both the public-key algorithm and the signature algorithm (per FIPS 204 and by analogous convention for KAZ-SIGN). RSA uses `1.2.840.113549.1.1.1` (`rsaEncryption`) for SPKI; ECDSA uses curve-specific OIDs (`1.2.840.10045.2.1` + named curve).

### DER encoder helper — used in Tasks 3–8

Each PQC validation signer needs `algorithm_identifier_der/0`. For an AlgorithmIdentifier with no parameters, the DER shape is:

```
SEQUENCE {
  OID <oid-bytes>
}
```

i.e. `0x30 <total-len> 0x06 <oid-len> <oid-bytes>`. A one-off helper encodes this. Every PQC signer has `@algorithm_identifier_der encode_alg_id(@oid_tuple)` computed at module load using a tiny `defp`.

**Helper code (copy verbatim into each PQC signer module):**

```elixir
  # Encode an AlgorithmIdentifier SEQUENCE with no parameters: 30 LL 06 OL <oid>
  @spec build_alg_id_der(tuple()) :: binary()
  defp build_alg_id_der(oid_tuple) do
    oid_der = :public_key.der_encode(:OBJECT_IDENTIFIER, oid_tuple)
    oid_len = byte_size(oid_der)
    <<0x30, oid_len, oid_der::binary>>
  end
```

(This produces a valid DER SEQUENCE containing only the OID. Parameters absent; suitable for ML-DSA and KAZ-SIGN per FIPS 204 / analogous convention.)

---

## Task 1: Create `PkiCrypto.AlgorithmRegistry` — classical entries only

**Files:**
- Create: `src/pki_crypto/lib/pki_crypto/algorithm_registry.ex`
- Create: `src/pki_crypto/test/pki_crypto/algorithm_registry_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_crypto/test/pki_crypto/algorithm_registry_test.exs`:

```elixir
defmodule PkiCrypto.AlgorithmRegistryTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.AlgorithmRegistry

  describe "by_id/1 for classical algorithms" do
    test "returns metadata for RSA-2048" do
      assert {:ok, %{id: "RSA-2048", family: :rsa, sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11}}} =
               AlgorithmRegistry.by_id("RSA-2048")
    end

    test "returns metadata for ECC-P256" do
      assert {:ok, %{id: "ECC-P256", family: :ecdsa, sig_alg_oid: {1, 2, 840, 10045, 4, 3, 2}}} =
               AlgorithmRegistry.by_id("ECC-P256")
    end

    test "returns metadata for ECC-P384" do
      assert {:ok, %{id: "ECC-P384", family: :ecdsa, sig_alg_oid: {1, 2, 840, 10045, 4, 3, 3}}} =
               AlgorithmRegistry.by_id("ECC-P384")
    end

    test "returns :error for unknown id" do
      assert :error = AlgorithmRegistry.by_id("NOT-AN-ALGO")
    end
  end

  describe "by_oid/1 for classical algorithms" do
    test "finds RSA-2048 by its sig_alg OID" do
      assert {:ok, %{id: "RSA-2048"}} = AlgorithmRegistry.by_oid({1, 2, 840, 113549, 1, 1, 11})
    end

    test "returns :error for unknown OID" do
      assert :error = AlgorithmRegistry.by_oid({1, 2, 3, 4, 5})
    end
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run from repo root:

```
cd src/pki_crypto && mix test test/pki_crypto/algorithm_registry_test.exs
```

Expected: compile error — `PkiCrypto.AlgorithmRegistry` undefined. Good, that means the test is wired.

- [ ] **Step 3: Write minimal implementation**

Create `src/pki_crypto/lib/pki_crypto/algorithm_registry.ex`:

```elixir
defmodule PkiCrypto.AlgorithmRegistry do
  @moduledoc """
  OID-aware metadata registry for X.509 cert/CSR emission and parsing.

  Complements `PkiCrypto.Registry` (which maps algorithm name strings to
  protocol-implementing structs for sign/verify dispatch) by adding the
  metadata X.509 emission needs: OIDs for `signatureAlgorithm` and
  `subjectPublicKeyInfo`, algorithm family (for code branching), and the
  `PkiCrypto.Registry` id used to reach the signing primitives.

  OIDs are overridable via `Application.get_env(:pki_crypto, :oid_overrides, %{})`
  keyed by algorithm id string — this lets deployments swap private OIDs
  (e.g. KAZ-SIGN placeholder → real Antrapol PEN) without code changes.

  ## Example

      iex> PkiCrypto.AlgorithmRegistry.by_id("ECC-P256")
      {:ok, %{id: "ECC-P256", family: :ecdsa,
              sig_alg_oid: {1, 2, 840, 10045, 4, 3, 2}, ...}}
  """

  @type algorithm_id :: String.t()
  @type oid :: :erlang.tuple()
  @type family :: :rsa | :ecdsa | :ml_dsa | :kaz_sign | :slh_dsa

  @type entry :: %{
          id: algorithm_id(),
          family: family(),
          sig_alg_oid: oid(),
          public_key_oid: oid()
        }

  # Defaults. OIDs here can be overridden per-id via config — see oid/1.
  @defaults %{
    "RSA-2048" => %{
      family: :rsa,
      sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11},
      public_key_oid: {1, 2, 840, 113549, 1, 1, 1}
    },
    "RSA-4096" => %{
      family: :rsa,
      sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11},
      public_key_oid: {1, 2, 840, 113549, 1, 1, 1}
    },
    "ECC-P256" => %{
      family: :ecdsa,
      sig_alg_oid: {1, 2, 840, 10045, 4, 3, 2},
      public_key_oid: {1, 2, 840, 10045, 2, 1}
    },
    "ECC-P384" => %{
      family: :ecdsa,
      sig_alg_oid: {1, 2, 840, 10045, 4, 3, 3},
      public_key_oid: {1, 2, 840, 10045, 2, 1}
    }
  }

  @doc "Look up an algorithm entry by its id string."
  @spec by_id(algorithm_id()) :: {:ok, entry()} | :error
  def by_id(id) when is_binary(id) do
    case Map.fetch(@defaults, id) do
      {:ok, base} -> {:ok, Map.merge(%{id: id}, apply_overrides(id, base))}
      :error -> :error
    end
  end

  @doc "Look up an algorithm entry by the signatureAlgorithm OID."
  @spec by_oid(oid()) :: {:ok, entry()} | :error
  def by_oid(oid) when is_tuple(oid) do
    Enum.find_value(@defaults, :error, fn {id, _base} ->
      {:ok, entry} = by_id(id)
      if entry.sig_alg_oid == oid, do: {:ok, entry}, else: nil
    end)
  end

  # --- Private ---

  defp apply_overrides(id, base) do
    overrides = Application.get_env(:pki_crypto, :oid_overrides, %{})

    case Map.get(overrides, id) do
      nil -> base
      custom when is_map(custom) -> Map.merge(base, Map.take(custom, [:sig_alg_oid, :public_key_oid]))
    end
  end
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd src/pki_crypto && mix test test/pki_crypto/algorithm_registry_test.exs`

Expected: 5 tests, 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/algorithm_registry.ex \
        src/pki_crypto/test/pki_crypto/algorithm_registry_test.exs
git commit -m "feat(pki_crypto): AlgorithmRegistry with classical entries + OID overrides"
```

---

## Task 2: Extend `AlgorithmRegistry` with PQC entries and exercise the override

**Files:**
- Modify: `src/pki_crypto/lib/pki_crypto/algorithm_registry.ex`
- Modify: `src/pki_crypto/test/pki_crypto/algorithm_registry_test.exs`

- [ ] **Step 1: Write the failing tests**

Append to `src/pki_crypto/test/pki_crypto/algorithm_registry_test.exs` inside the existing `defmodule`:

```elixir
  describe "by_id/1 for PQC algorithms" do
    test "returns metadata for ML-DSA-44" do
      assert {:ok, %{id: "ML-DSA-44", family: :ml_dsa,
                     sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 17}}} =
               AlgorithmRegistry.by_id("ML-DSA-44")
    end

    test "returns metadata for ML-DSA-65" do
      assert {:ok, %{id: "ML-DSA-65", sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 18}}} =
               AlgorithmRegistry.by_id("ML-DSA-65")
    end

    test "returns metadata for ML-DSA-87" do
      assert {:ok, %{id: "ML-DSA-87", sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 19}}} =
               AlgorithmRegistry.by_id("ML-DSA-87")
    end

    test "returns metadata for KAZ-SIGN-128 with placeholder OID" do
      assert {:ok, %{id: "KAZ-SIGN-128", family: :kaz_sign,
                     sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-128")
    end

    test "returns metadata for KAZ-SIGN-192 with placeholder OID" do
      assert {:ok, %{id: "KAZ-SIGN-192", sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-192")
    end

    test "returns metadata for KAZ-SIGN-256 with placeholder OID" do
      assert {:ok, %{id: "KAZ-SIGN-256", sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 3}}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-256")
    end
  end

  describe "OID override" do
    setup do
      original = Application.get_env(:pki_crypto, :oid_overrides, %{})

      on_exit(fn ->
        Application.put_env(:pki_crypto, :oid_overrides, original)
      end)

      :ok
    end

    test "override replaces sig_alg_oid for KAZ-SIGN-192" do
      real_oid = {1, 3, 6, 1, 4, 1, 55555, 1, 1, 2}

      Application.put_env(:pki_crypto, :oid_overrides, %{
        "KAZ-SIGN-192" => %{sig_alg_oid: real_oid, public_key_oid: real_oid}
      })

      assert {:ok, %{id: "KAZ-SIGN-192", sig_alg_oid: ^real_oid, public_key_oid: ^real_oid}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-192")
    end
  end
```

- [ ] **Step 2: Run to verify fails**

Run: `cd src/pki_crypto && mix test test/pki_crypto/algorithm_registry_test.exs`

Expected: 7 new tests fail with `:error = {:ok, ...}` mismatches (PQC ids not in `@defaults`).

- [ ] **Step 3: Add PQC entries**

In `src/pki_crypto/lib/pki_crypto/algorithm_registry.ex`, extend `@defaults`:

```elixir
  @defaults %{
    "RSA-2048" => %{
      family: :rsa,
      sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11},
      public_key_oid: {1, 2, 840, 113549, 1, 1, 1}
    },
    "RSA-4096" => %{
      family: :rsa,
      sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11},
      public_key_oid: {1, 2, 840, 113549, 1, 1, 1}
    },
    "ECC-P256" => %{
      family: :ecdsa,
      sig_alg_oid: {1, 2, 840, 10045, 4, 3, 2},
      public_key_oid: {1, 2, 840, 10045, 2, 1}
    },
    "ECC-P384" => %{
      family: :ecdsa,
      sig_alg_oid: {1, 2, 840, 10045, 4, 3, 3},
      public_key_oid: {1, 2, 840, 10045, 2, 1}
    },
    # NIST ML-DSA — FIPS 204 OIDs
    "ML-DSA-44" => %{
      family: :ml_dsa,
      sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 17},
      public_key_oid: {2, 16, 840, 1, 101, 3, 4, 3, 17}
    },
    "ML-DSA-65" => %{
      family: :ml_dsa,
      sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 18},
      public_key_oid: {2, 16, 840, 1, 101, 3, 4, 3, 18}
    },
    "ML-DSA-87" => %{
      family: :ml_dsa,
      sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 19},
      public_key_oid: {2, 16, 840, 1, 101, 3, 4, 3, 19}
    },
    # KAZ-SIGN — PLACEHOLDER PEN (99999). Replace before production via
    # config :pki_crypto, :oid_overrides, %{"KAZ-SIGN-192" => %{...}}
    "KAZ-SIGN-128" => %{
      family: :kaz_sign,
      sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1},
      public_key_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}
    },
    "KAZ-SIGN-192" => %{
      family: :kaz_sign,
      sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2},
      public_key_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}
    },
    "KAZ-SIGN-256" => %{
      family: :kaz_sign,
      sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 3},
      public_key_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 3}
    }
  }
```

- [ ] **Step 4: Run tests to verify all pass**

Run: `cd src/pki_crypto && mix test test/pki_crypto/algorithm_registry_test.exs`

Expected: 12 tests, 12 passed (5 from Task 1 + 7 new).

- [ ] **Step 5: Commit**

```bash
git add src/pki_crypto/lib/pki_crypto/algorithm_registry.ex \
        src/pki_crypto/test/pki_crypto/algorithm_registry_test.exs
git commit -m "feat(pki_crypto): register ML-DSA + KAZ-SIGN (placeholder OIDs) in AlgorithmRegistry"
```

---

## Task 3: `PkiValidation.Crypto.Signer.MlDsa44` — the first PQC validation signer

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_44.ex`
- Create: `src/pki_validation/test/pki_validation/crypto/signer/ml_dsa_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/crypto/signer/ml_dsa_test.exs`:

```elixir
defmodule PkiValidation.Crypto.Signer.MlDsaTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.MlDsa44

  describe "MlDsa44 behaviour conformance" do
    test "sign/verify round-trip via pki_crypto NIF" do
      algo = PkiCrypto.Registry.get("ML-DSA-44")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)

      tbs = "tbs-bytes-placeholder"
      decoded = MlDsa44.decode_private_key(sk)
      assert is_binary(decoded)

      signature = MlDsa44.sign(tbs, decoded)
      assert is_binary(signature)
      assert byte_size(signature) > 0

      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, tbs)
    end

    test "algorithm_identifier_der/0 emits SEQUENCE(OID) DER" do
      der = MlDsa44.algorithm_identifier_der()
      # 30 = SEQUENCE, 06 = OID. Decoding must round-trip via :public_key.
      assert <<0x30, _total_len, 0x06, _oid_len, _rest::binary>> = der
    end

    test "algorithm_identifier_record/0 is a 3-tuple :AlgorithmIdentifier" do
      assert {:AlgorithmIdentifier, {2, 16, 840, 1, 101, 3, 4, 3, 17}, :asn1_NOVALUE} =
               MlDsa44.algorithm_identifier_record()
    end
  end
end
```

- [ ] **Step 2: Run to verify fails**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/ml_dsa_test.exs`

Expected: compile error — `MlDsa44` undefined.

- [ ] **Step 3: Implement `MlDsa44`**

Create `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_44.ex`:

```elixir
defmodule PkiValidation.Crypto.Signer.MlDsa44 do
  @moduledoc """
  ML-DSA-44 (FIPS 204) OCSP/CRL signer. Private key bytes are raw output from
  `PkiCrypto.Algorithm.generate_keypair/1` — no encoding at rest. `decode_private_key/1`
  is a pass-through (the NIF accepts raw bytes).
  """
  @behaviour PkiValidation.Crypto.Signer

  @oid {2, 16, 840, 1, 101, 3, 4, 3, 17}
  # Precomputed DER: SEQUENCE(OID 2.16.840.1.101.3.4.3.17)
  # Equivalent to: <<0x30, byte_size(der)>> <> :public_key.der_encode(:OBJECT_IDENTIFIER, @oid)
  @algorithm_identifier_der <<0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = PkiOqsNif.sign("ML-DSA-44", private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
```

If the test in Step 1 fails with a byte mismatch, re-derive the DER in iex and update the `@algorithm_identifier_der` attribute to match:

```
iex> der = :public_key.der_encode(:OBJECT_IDENTIFIER, {2, 16, 840, 1, 101, 3, 4, 3, 17})
iex> <<0x30, byte_size(der)>> <> der
<<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 3, 17>>
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/ml_dsa_test.exs`

Expected: 3 tests, 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_44.ex \
        src/pki_validation/test/pki_validation/crypto/signer/ml_dsa_test.exs
git commit -m "feat(pki_validation): ML-DSA-44 signer (FIPS 204)"
```

---

## Task 4: `MlDsa65` and `MlDsa87` — the sibling variants

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_65.ex`
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_87.ex`
- Modify: `src/pki_validation/test/pki_validation/crypto/signer/ml_dsa_test.exs`

- [ ] **Step 1: Extend the test file**

Append to `src/pki_validation/test/pki_validation/crypto/signer/ml_dsa_test.exs`:

```elixir
  describe "MlDsa65 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.MlDsa65

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("ML-DSA-65")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = MlDsa65.sign("tbs-65", MlDsa65.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-65")
    end

    test "algorithm_identifier_record uses OID 2.16.840.1.101.3.4.3.18" do
      assert {:AlgorithmIdentifier, {2, 16, 840, 1, 101, 3, 4, 3, 18}, :asn1_NOVALUE} =
               MlDsa65.algorithm_identifier_record()
    end
  end

  describe "MlDsa87 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.MlDsa87

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("ML-DSA-87")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = MlDsa87.sign("tbs-87", MlDsa87.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-87")
    end

    test "algorithm_identifier_record uses OID 2.16.840.1.101.3.4.3.19" do
      assert {:AlgorithmIdentifier, {2, 16, 840, 1, 101, 3, 4, 3, 19}, :asn1_NOVALUE} =
               MlDsa87.algorithm_identifier_record()
    end
  end
```

- [ ] **Step 2: Run to verify fails**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/ml_dsa_test.exs`

Expected: 4 new tests fail with `MlDsa65` / `MlDsa87` undefined.

- [ ] **Step 3: Create `MlDsa65` module**

Create `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_65.ex`:

```elixir
defmodule PkiValidation.Crypto.Signer.MlDsa65 do
  @moduledoc "ML-DSA-65 (FIPS 204) OCSP/CRL signer. See `MlDsa44` for details."
  @behaviour PkiValidation.Crypto.Signer

  @oid {2, 16, 840, 1, 101, 3, 4, 3, 18}
  # 30 0b 06 09 60 86 48 01 65 03 04 03 12
  @algorithm_identifier_der <<0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = PkiOqsNif.sign("ML-DSA-65", private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
```

- [ ] **Step 4: Create `MlDsa87` module**

Create `src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_87.ex`:

```elixir
defmodule PkiValidation.Crypto.Signer.MlDsa87 do
  @moduledoc "ML-DSA-87 (FIPS 204) OCSP/CRL signer. See `MlDsa44` for details."
  @behaviour PkiValidation.Crypto.Signer

  @oid {2, 16, 840, 1, 101, 3, 4, 3, 19}
  # 30 0b 06 09 60 86 48 01 65 03 04 03 13
  @algorithm_identifier_der <<0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = PkiOqsNif.sign("ML-DSA-87", private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
```

- [ ] **Step 5: Run all ML-DSA tests**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/ml_dsa_test.exs`

Expected: 7 tests, 7 passed.

- [ ] **Step 6: Commit**

```bash
git add src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_65.ex \
        src/pki_validation/lib/pki_validation/crypto/signer/ml_dsa_87.ex \
        src/pki_validation/test/pki_validation/crypto/signer/ml_dsa_test.exs
git commit -m "feat(pki_validation): ML-DSA-65 and ML-DSA-87 signers"
```

---

## Task 5: `KazSign128` — the first KAZ-SIGN validation signer

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_128.ex`
- Create: `src/pki_validation/test/pki_validation/crypto/signer/kaz_sign_test.exs`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/crypto/signer/kaz_sign_test.exs`:

```elixir
defmodule PkiValidation.Crypto.Signer.KazSignTest do
  use ExUnit.Case, async: true

  describe "KazSign128 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.KazSign128

    test "sign/verify round-trip via pki_crypto" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-128")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)

      tbs = "tbs-bytes"
      signature = KazSign128.sign(tbs, KazSign128.decode_private_key(sk))
      assert is_binary(signature) and byte_size(signature) > 0

      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, tbs)
    end

    test "algorithm_identifier_record uses placeholder OID" do
      assert {:AlgorithmIdentifier, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}, :asn1_NOVALUE} =
               KazSign128.algorithm_identifier_record()
    end

    test "algorithm_identifier_der starts with SEQUENCE + OID tag" do
      <<0x30, _len, 0x06, _oid_len, _rest::binary>> = KazSign128.algorithm_identifier_der()
    end
  end
end
```

- [ ] **Step 2: Run to verify fails**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/kaz_sign_test.exs`

Expected: compile error — `KazSign128` undefined.

- [ ] **Step 3: Implement `KazSign128`**

First compute the DER bytes for the placeholder OID:

```
iex> der = :public_key.der_encode(:OBJECT_IDENTIFIER, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1})
iex> <<0x30, byte_size(der)>> <> der
<<48, 13, 6, 11, 43, 6, 1, 4, 1, 134, 141, 31, 1, 1, 1>>
```

(The PEN `99999` encodes as two high bytes `0x86 0x8D 0x1F` plus the final `0x1F` due to base-128 variable-length encoding for the sub-identifier.)

Create `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_128.ex`:

```elixir
defmodule PkiValidation.Crypto.Signer.KazSign128 do
  @moduledoc """
  KAZ-SIGN-128 (Malaysia PQC) OCSP/CRL signer.

  OID is a PLACEHOLDER (`1.3.6.1.4.1.99999.1.1.1`) pending Antrapolation's
  IANA PEN assignment. Override via
  `config :pki_crypto, :oid_overrides, %{"KAZ-SIGN-128" => %{sig_alg_oid: ...}}`
  once the real OID lands — this module reads its OID at compile time, so
  a config override requires a rebuild, or replace @oid manually and rebuild.
  """
  @behaviour PkiValidation.Crypto.Signer

  @oid {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}
  # 30 0d 06 0b 2b 06 01 04 01 86 8d 1f 01 01 01
  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x01, 0x01>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = KazSign.sign(128, private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/kaz_sign_test.exs`

Expected: 3 tests, 3 passed.

If the DER assertion fails, re-derive the bytes via iex using the actual `:public_key.der_encode` output and update `@algorithm_identifier_der` to match. Do not try to derive it by hand.

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_128.ex \
        src/pki_validation/test/pki_validation/crypto/signer/kaz_sign_test.exs
git commit -m "feat(pki_validation): KAZ-SIGN-128 signer with placeholder OID"
```

---

## Task 6: `KazSign192` and `KazSign256`

**Files:**
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_192.ex`
- Create: `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_256.ex`
- Modify: `src/pki_validation/test/pki_validation/crypto/signer/kaz_sign_test.exs`

- [ ] **Step 1: Extend tests**

Append to `src/pki_validation/test/pki_validation/crypto/signer/kaz_sign_test.exs`:

```elixir
  describe "KazSign192 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.KazSign192

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = KazSign192.sign("tbs-192", KazSign192.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-192")
    end

    test "algorithm_identifier_record uses placeholder OID .2" do
      assert {:AlgorithmIdentifier, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}, :asn1_NOVALUE} =
               KazSign192.algorithm_identifier_record()
    end
  end

  describe "KazSign256 behaviour conformance" do
    alias PkiValidation.Crypto.Signer.KazSign256

    test "sign/verify round-trip" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-256")
      {:ok, %{public_key: pk, private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
      signature = KazSign256.sign("tbs-256", KazSign256.decode_private_key(sk))
      assert :ok = PkiCrypto.Algorithm.verify(algo, pk, signature, "tbs-256")
    end

    test "algorithm_identifier_record uses placeholder OID .3" do
      assert {:AlgorithmIdentifier, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 3}, :asn1_NOVALUE} =
               KazSign256.algorithm_identifier_record()
    end
  end
```

- [ ] **Step 2: Run to verify fails**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/kaz_sign_test.exs`

Expected: 4 new tests fail (`KazSign192` / `KazSign256` undefined).

- [ ] **Step 3: Create `KazSign192`**

Create `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_192.ex`:

```elixir
defmodule PkiValidation.Crypto.Signer.KazSign192 do
  @moduledoc "KAZ-SIGN-192 OCSP/CRL signer. See `KazSign128` for details on placeholder OIDs."
  @behaviour PkiValidation.Crypto.Signer

  @oid {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}
  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x01, 0x02>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = KazSign.sign(192, private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
```

- [ ] **Step 4: Create `KazSign256`**

Create `src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_256.ex`:

```elixir
defmodule PkiValidation.Crypto.Signer.KazSign256 do
  @moduledoc "KAZ-SIGN-256 OCSP/CRL signer. See `KazSign128` for details on placeholder OIDs."
  @behaviour PkiValidation.Crypto.Signer

  @oid {1, 3, 6, 1, 4, 1, 99999, 1, 1, 3}
  @algorithm_identifier_der <<0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x01, 0x03>>

  @impl true
  def decode_private_key(raw) when is_binary(raw), do: raw

  @impl true
  def sign(tbs, private_key) when is_binary(tbs) and is_binary(private_key) do
    {:ok, sig} = KazSign.sign(256, private_key, tbs)
    sig
  end

  @impl true
  def algorithm_identifier_der, do: @algorithm_identifier_der

  @impl true
  def algorithm_identifier_record, do: {:AlgorithmIdentifier, @oid, :asn1_NOVALUE}
end
```

- [ ] **Step 5: Run all KAZ-SIGN tests**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/kaz_sign_test.exs`

Expected: 7 tests, 7 passed.

- [ ] **Step 6: Commit**

```bash
git add src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_192.ex \
        src/pki_validation/lib/pki_validation/crypto/signer/kaz_sign_256.ex \
        src/pki_validation/test/pki_validation/crypto/signer/kaz_sign_test.exs
git commit -m "feat(pki_validation): KAZ-SIGN-192 and KAZ-SIGN-256 signers"
```

---

## Task 7: Register all six PQC signers in `PkiValidation.Crypto.Signer.Registry`

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/crypto/signer/registry.ex`

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/crypto/signer/registry_pqc_test.exs`:

```elixir
defmodule PkiValidation.Crypto.Signer.RegistryPqcTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Registry

  describe "PQC algorithm resolution" do
    test "ML-DSA-44 maps to MlDsa44 module" do
      assert {:ok, PkiValidation.Crypto.Signer.MlDsa44} = Registry.fetch("ml_dsa_44")
    end

    test "ML-DSA-65 maps to MlDsa65 module" do
      assert {:ok, PkiValidation.Crypto.Signer.MlDsa65} = Registry.fetch("ml_dsa_65")
    end

    test "ML-DSA-87 maps to MlDsa87 module" do
      assert {:ok, PkiValidation.Crypto.Signer.MlDsa87} = Registry.fetch("ml_dsa_87")
    end

    test "KAZ-SIGN-128 maps to KazSign128 module" do
      assert {:ok, PkiValidation.Crypto.Signer.KazSign128} = Registry.fetch("kaz_sign_128")
    end

    test "KAZ-SIGN-192 maps to KazSign192 module" do
      assert {:ok, PkiValidation.Crypto.Signer.KazSign192} = Registry.fetch("kaz_sign_192")
    end

    test "KAZ-SIGN-256 maps to KazSign256 module" do
      assert {:ok, PkiValidation.Crypto.Signer.KazSign256} = Registry.fetch("kaz_sign_256")
    end

    test "algorithms/0 includes all six PQC strings" do
      algos = Registry.algorithms()

      for id <- ~w[ml_dsa_44 ml_dsa_65 ml_dsa_87 kaz_sign_128 kaz_sign_192 kaz_sign_256] do
        assert id in algos, "expected #{id} in #{inspect(algos)}"
      end
    end
  end
end
```

- [ ] **Step 2: Run to verify fails**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/registry_pqc_test.exs`

Expected: 7 tests fail (each `fetch/1` returns `:error`).

- [ ] **Step 3: Extend the registry**

Modify `src/pki_validation/lib/pki_validation/crypto/signer/registry.ex`. Find the existing `@mapping` and append:

```elixir
  alias PkiValidation.Crypto.Signer.{
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa4096,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    KazSign128,
    KazSign192,
    KazSign256
  }

  @mapping %{
    "ecc_p256" => EcdsaP256,
    "ecc_p384" => EcdsaP384,
    "rsa2048" => Rsa2048,
    "rsa4096" => Rsa4096,
    "ml_dsa_44" => MlDsa44,
    "ml_dsa_65" => MlDsa65,
    "ml_dsa_87" => MlDsa87,
    "kaz_sign_128" => KazSign128,
    "kaz_sign_192" => KazSign192,
    "kaz_sign_256" => KazSign256
  }
```

Do not touch the existing `fetch/1` / `algorithms/0` / `@algorithms` derivations — they're keyed off `@mapping` and pick up the new entries automatically.

- [ ] **Step 4: Run tests to verify all pass**

Run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/registry_pqc_test.exs`

Expected: 7 tests, 7 passed.

Also run: `cd src/pki_validation && mix test test/pki_validation/crypto/signer/registry_test.exs`

Expected: existing classical registry tests still pass.

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/crypto/signer/registry.ex \
        src/pki_validation/test/pki_validation/crypto/signer/registry_pqc_test.exs
git commit -m "feat(pki_validation): register ML-DSA and KAZ-SIGN signers"
```

---

## Task 8: Extend `SigningKeyConfig.@valid_algorithms`

**Files:**
- Modify: `src/pki_validation/lib/pki_validation/schema/signing_key_config.ex`

The `Signer.Registry` algorithms list is the source of truth per its `@doc`. We update `SigningKeyConfig` to read from the Registry instead of maintaining a duplicate list. This prevents drift (the whole reason `Registry.algorithms/0` exists).

- [ ] **Step 1: Write the failing test**

Create `src/pki_validation/test/pki_validation/schema/signing_key_config_pqc_test.exs`:

```elixir
defmodule PkiValidation.Schema.SigningKeyConfigPqcTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Schema.SigningKeyConfig

  describe "changeset/2 algorithm validation" do
    test "accepts ML-DSA-44" do
      attrs = valid_attrs(%{algorithm: "ml_dsa_44"})
      cs = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
      assert cs.valid?, "expected valid, got #{inspect(cs.errors)}"
    end

    test "accepts KAZ-SIGN-192" do
      attrs = valid_attrs(%{algorithm: "kaz_sign_192"})
      cs = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
      assert cs.valid?, "expected valid, got #{inspect(cs.errors)}"
    end

    test "rejects unknown algorithm" do
      attrs = valid_attrs(%{algorithm: "not_real"})
      cs = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
      refute cs.valid?
      assert {_, _} = cs.errors[:algorithm]
    end
  end

  defp valid_attrs(overrides) do
    Map.merge(
      %{
        issuer_key_id: "abc",
        algorithm: "ecc_p256",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        encrypted_private_key: <<0, 1, 2>>,
        not_before: DateTime.utc_now(),
        not_after: DateTime.utc_now() |> DateTime.add(365 * 86400, :second),
        status: "active"
      },
      overrides
    )
  end
end
```

- [ ] **Step 2: Run to verify fails**

Run: `cd src/pki_validation && mix test test/pki_validation/schema/signing_key_config_pqc_test.exs`

Expected: 2 new tests fail (`ml_dsa_44`, `kaz_sign_192` rejected as invalid).

- [ ] **Step 3: Modify the schema to look up algorithms at runtime via Registry**

Read the existing file at `src/pki_validation/lib/pki_validation/schema/signing_key_config.ex` first. Locate `@valid_algorithms` (a module attribute) and the `validate_inclusion(:algorithm, @valid_algorithms)` call inside the changeset.

Remove the `@valid_algorithms` attribute entirely. Replace the validate_inclusion call with a runtime lookup so the source of truth stays in `Signer.Registry` and drift is impossible:

```elixir
    |> validate_inclusion(:algorithm, PkiValidation.Crypto.Signer.Registry.algorithms())
```

Runtime lookup is chosen over compile-time capture to avoid compile-order issues (SigningKeyConfig is compiled before or during the same pass as Registry).

- [ ] **Step 4: Run tests to verify**

Run: `cd src/pki_validation && mix test test/pki_validation/schema/signing_key_config_pqc_test.exs test/pki_validation/schema/signing_key_config_test.exs`

Expected: all tests pass (new PQC tests + existing classical tests).

- [ ] **Step 5: Commit**

```bash
git add src/pki_validation/lib/pki_validation/schema/signing_key_config.ex \
        src/pki_validation/test/pki_validation/schema/signing_key_config_pqc_test.exs
git commit -m "feat(pki_validation): accept PQC algorithms in SigningKeyConfig (derive from Registry)"
```

---

## Task 9: Full `mix test` regression across the umbrella

**Files:** _(no edits — verification only)_

- [ ] **Step 1: Run every validation-engine test**

Run: `cd src/pki_validation && mix test`

Expected: 100% pass. In particular:
- Existing OCSP/CRL signing tests (classical) still pass — we did not touch the classical signer modules.
- `SigningKeyStore` tests still pass — the store iterates `@mapping`, so it now sees 10 algorithms but we haven't inserted any PQC SigningKeyConfig rows yet, so behaviour is unchanged.

- [ ] **Step 2: Run every pki_crypto test**

Run: `cd src/pki_crypto && mix test`

Expected: 100% pass — AlgorithmRegistry tests + existing protocol/NIF tests.

- [ ] **Step 3: Compile the umbrella**

Run: `cd /Users/amirrudinyahaya/Workspace/pki && mix compile 2>&1 | tail -20`

Expected: clean compile (warnings are fine if pre-existing). No new errors involving the new modules.

- [ ] **Step 4: Commit a verification marker (optional)**

No code change; this step only exists to surface failures before the phase is declared done. If any test fails, stop and diagnose before proceeding.

---

## Task 10: Smoke test on the VPS

**Files:** _(no edits — manual smoke verification on the deployment target)_

This task is performed by the operator after merge + deploy. It confirms the Phase 1 code loads and the PQC signer modules are callable in a running release.

- [ ] **Step 1: Redeploy to the VPS**

Standard rebuild + deploy sequence:

```bash
# local
git push

# VPS
cd ~/pki && git pull
set -a; source <(sudo cat /opt/pki/.env); set +a
sudo rm -rf _build/prod/rel
bash deploy/build.sh 2>&1 | tail -5
sudo bash deploy/deploy.sh 2>&1 | tail -10
sleep 15
sudo systemctl is-active pki-engines pki-portals pki-audit
```

Expected: all three services `active`.

- [ ] **Step 2: Verify PQC signers are loadable in the running VM**

On the VPS:

```bash
sudo -u pki bash -c "set -a; source /opt/pki/.env; set +a; /opt/pki/releases/portals/bin/pki_portals eval '
  alias PkiValidation.Crypto.Signer.{MlDsa44, KazSign192}
  IO.inspect(Code.ensure_loaded?(MlDsa44), label: :ml_dsa_44_loaded)
  IO.inspect(Code.ensure_loaded?(KazSign192), label: :kaz_sign_192_loaded)
  IO.inspect(MlDsa44.algorithm_identifier_record(), label: :ml_dsa_44_alg_id)
  IO.inspect(KazSign192.algorithm_identifier_record(), label: :kaz_sign_192_alg_id)
'"
```

Expected output:

```
ml_dsa_44_loaded: true
kaz_sign_192_loaded: true
ml_dsa_44_alg_id: {:AlgorithmIdentifier, {2, 16, 840, 1, 101, 3, 4, 3, 17}, :asn1_NOVALUE}
kaz_sign_192_alg_id: {:AlgorithmIdentifier, {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}, :asn1_NOVALUE}
```

- [ ] **Step 3: Confirm Phase 1 definition of done**

Phase 1 is complete when:
- `PkiCrypto.AlgorithmRegistry` compiles, is unit-tested, and supports OID overrides via config.
- All six PQC signer modules (`MlDsa{44,65,87}` + `KazSign{128,192,256}`) are present, conform to the `Signer` behaviour, and pass round-trip sign/verify tests.
- `PkiValidation.Crypto.Signer.Registry.algorithms/0` reports 10 algorithms.
- `SigningKeyConfig` accepts all 10.
- No existing code path changed behaviour; classical signing still works.
- VPS smoke test shows PQC signer modules loadable at runtime.

---

## Out-of-scope for Phase 1 (do NOT attempt)

- Parsing PQC CSRs — Phase 2.
- Emitting X.509 certs with PQC subject or PQC issuer — Phase 2 (subject) and Phase 3 (issuer).
- Retiring the JSON-wrapper cert format in `PkiCaEngine.CertificateSigning` — Phase 3.
- Hooking `SigningKeyStore` to actually load a PQC key row — Phase 4 (requires a CA in PQC mode which doesn't exist until Phase 3 ships).
- Exercising OCSP/CRL with PQC signing — Phase 4.
- Updating the Antrapol PEN placeholder (`99999`) to the real IANA-assigned PEN — requires external allocation; track as a separate ticket.

---

## Phase 1 exit signal

When all tasks above are checked off and the VPS smoke test passes, this plan is done. The next plan (Phase 2 — classical issuer, PQC subject) will consume `AlgorithmRegistry` and the PQC signer modules as its foundation.
