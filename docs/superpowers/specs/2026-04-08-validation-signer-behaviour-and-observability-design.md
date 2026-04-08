# Validation Service: Signer Behaviour + SigningKeyStore Observability

**Date:** 2026-04-08
**Status:** Approved
**Branch:** `feat/validation-followups`
**Builds on:** `docs/superpowers/specs/2026-04-07-validation-service-rfc-compliance-design.md`

## Goal

Two follow-ups surfaced by the final pre-merge review of the RFC compliance feature (PR #4, merged as `5406750`):

1. **Extract a `PkiValidation.Crypto.Signer` behaviour** so adding a new signing algorithm (ML-DSA, SLH-DSA, KAZ-SIGN) touches one new module instead of five sites across the codebase.
2. **Add `SigningKeyStore.status/0` + `/health` degradation** so partial or total key-load failures are visible via HTTP health checks instead of surfacing only as `:unauthorized` responses under load.

Order of work: **observability first** (smaller, additive, acts as a debugging aid during the behaviour refactor), then **behaviour extraction**.

## Part 1 — SigningKeyStore Observability

### Current behaviour (problematic)

`SigningKeyStore.load_keys/1` iterates active `SigningKeyConfig` rows, tries to decrypt each one, and silently drops any that fail decryption (logging an error line). This is the "drop but don't crash" contract that prevents a single corrupt row from taking the whole responder offline — intentional, still correct. The problem is that **operators have no signal that this happened** short of grepping logs. A misconfigured deployment passes startup, `/health` returns 200, and every signed response the service would have produced comes back as `:unauthorized` instead.

### New behaviour

`SigningKeyStore` tracks two new pieces of state at load time:

- `loaded_count :: non_neg_integer()` — successfully decrypted + parsed keys
- `failed` — a list of `%{issuer_key_id, reason :: atom()}` entries (capped at the most recent 50 to prevent unbounded growth on many-key deployments)

Expose via a new public function:

```elixir
@type status :: %{
        loaded: non_neg_integer(),
        failed: non_neg_integer(),
        last_error: atom() | nil,
        healthy: boolean()
      }

@spec status(GenServer.server()) :: status()
def status(server \\ __MODULE__)
```

Where `healthy` is `true` iff `failed == 0`. The internal failure list is summarised into counts + last-error atom to keep the API surface small and avoid leaking decryption failure details (error reasons are already recorded in logs at `:error` level).

`last_error` is an atom from the existing failure enum (`:decryption_failed`, `:malformed_ciphertext`, `:invalid_cert_pem`) — deterministic, no binary data, safe to surface.

### `/health` endpoint integration

Current behaviour:

```elixir
get "/health" do
  send_json(conn, 200, %{status: "ok"})
end
```

Replaced with:

```elixir
get "/health" do
  case PkiValidation.SigningKeyStore.status() do
    %{healthy: true, loaded: n} ->
      send_json(conn, 200, %{status: "ok", signing_keys_loaded: n})

    %{loaded: n, failed: f, last_error: err} ->
      send_json(conn, 503, %{
        status: "degraded",
        signing_keys_loaded: n,
        signing_keys_failed: f,
        last_error: to_string(err)
      })
  end
end
```

**Strict policy** (option A from the design discussion): any failed key puts `/health` into 503. Operators must fix or deactivate the failing row to restore a healthy status. Rationale: silent partial failures are exactly the problem we're solving; lenient 200 on "at least one key loaded" would defeat the purpose.

### Reload semantics

`SigningKeyStore.reload/1` must recompute the status. The existing reload call already rebuilds the `keys` map via `load_keys/1`; the new code tracks `loaded_count` and `failed` during that same pass.

### Tests

- `status/1` returns healthy state when all keys load
- `status/1` reports failed count + last_error when some keys fail decryption
- `status/1` reports zero loaded + non-nil last_error when every key fails
- `/health` returns 200 + `healthy: true` JSON when store is healthy
- `/health` returns 503 + `status: "degraded"` when store has failures

Reuses the existing test patterns: insert a good key + a bad key (wrong password / malformed ciphertext), start a fresh store instance, observe status.

## Part 2 — Signer Behaviour Extraction

### Current problem

Adding a new signing algorithm today means editing **five places**:

1. Add the string to `SigningKeyConfig.@valid_algorithms`
2. Add a `sign_tbs/2` clause to `ResponseBuilder`
3. Add an `AlgorithmIdentifier` DER blob module attribute to `ResponseBuilder`
4. Add a `sign_tbs/2` clause to `DerGenerator`
5. Add a `sig_alg_identifier/1` clause to `DerGenerator`

Plus the algorithm-dependent private key shape (raw EC scalar vs DER-encoded `RSAPrivateKey` vs raw PQC secret) is handled inconsistently at call sites instead of being the signer's concern.

This is the biggest latent maintenance cost in the branch. PQC work (ML-DSA, SLH-DSA, KAZ-SIGN) is on the roadmap, and each new algorithm will compound the pain.

### New design

A behaviour module `PkiValidation.Crypto.Signer` with **three callbacks**:

```elixir
defmodule PkiValidation.Crypto.Signer do
  @moduledoc """
  Behaviour for OCSP/CRL signing algorithms.

  Each concrete signer module owns:
    - the AlgorithmIdentifier DER blob (RFC 5754 form)
    - private key decoding (raw bytes -> Erlang term usable by :public_key.sign/3)
    - the sign-tbs primitive

  SigningKeyStore calls `decode_private_key/1` once at load time and caches
  the decoded term in process state. Signers are then called with the
  pre-decoded key, avoiding per-signature parsing.
  """

  @doc "Decode the at-rest private key bytes into the form :public_key.sign/3 expects."
  @callback decode_private_key(binary()) :: term()

  @doc "Sign the TBS DER bytes, returning the raw signature bytes."
  @callback sign(tbs :: binary(), private_key :: term()) :: binary()

  @doc """
  Return the DER-encoded AlgorithmIdentifier for this signer.

  This is the pre-encoded byte sequence for RFC 5754 AlgorithmIdentifier with
  the algorithm OID and (for RSA) the NULL params, ready to splice into the
  OCSP.asn1 ANY-typed field.
  """
  @callback algorithm_identifier_der() :: binary()
end
```

**Why three callbacks, not one:**

- `decode_private_key/1` is the perf-critical seam — doing it at load time (once per key) instead of at sign time (every request) avoids the D1-like RSA bug and matches the H1 perf lesson from Phase 2.5.
- `algorithm_identifier_der/0` is static per module — it's a pre-encoded DER blob that never changes, so each signer module owns its own OID + params.
- `sign/2` is the single primitive — takes pre-decoded key, returns raw signature bytes. The caller wraps in the ASN.1 record.

### Concrete modules

Initial modules, one per algorithm:

| Module | Algorithm atom | Curve / Key size | Digest |
|---|---|---|---|
| `PkiValidation.Crypto.Signer.EcdsaP256` | `:ecc_p256` | secp256r1 | SHA-256 |
| `PkiValidation.Crypto.Signer.EcdsaP384` | `:ecc_p384` | secp384r1 | SHA-384 |
| `PkiValidation.Crypto.Signer.Rsa2048` | `:rsa2048` | 2048-bit | SHA-256 |
| `PkiValidation.Crypto.Signer.Rsa4096` | `:rsa4096` | 4096-bit | SHA-256 |

Each module is a thin wrapper that delegates to `:public_key.sign/3` with the right record shape. The RSA modules call `:public_key.der_decode(:RSAPrivateKey, der)` inside `decode_private_key/1` so the store holds the parsed record from then on — this kills the D1 RSA-crash bug at the source by making it structurally impossible to reach `sign/2` with undecoded bytes.

### Registry

A small registry module maps algorithm strings (from the DB) to signer modules:

```elixir
defmodule PkiValidation.Crypto.Signer.Registry do
  @moduledoc """
  Maps algorithm strings from SigningKeyConfig to concrete Signer modules.
  """

  @mapping %{
    "ecc_p256" => PkiValidation.Crypto.Signer.EcdsaP256,
    "ecc_p384" => PkiValidation.Crypto.Signer.EcdsaP384,
    "rsa2048" => PkiValidation.Crypto.Signer.Rsa2048,
    "rsa4096" => PkiValidation.Crypto.Signer.Rsa4096
  }

  @spec fetch(String.t()) :: {:ok, module()} | :error
  def fetch(algorithm), do: Map.fetch(@mapping, algorithm)
end
```

Adding ML-DSA or KAZ-SIGN in the future means:
1. Add the `@valid_algorithms` string to `SigningKeyConfig`
2. Create `PkiValidation.Crypto.Signer.MlDsa65` (or similar)
3. Add one line to `@mapping` in the Registry

**Three sites, not five, and no duplication across OCSP/CRL.**

### SigningKeyStore changes

`load_keys/1` resolves the signer module at load time and caches it + the decoded private key in the in-memory map:

```elixir
%{
  algorithm: config.algorithm,           # original string, for display/debugging
  signer: signer_mod,                    # the resolved Signer module
  private_key: decoded_priv,             # signer_mod.decode_private_key/1 output
  certificate_der: cert_der,
  key_hash: PkiValidation.CertId.issuer_key_hash(cert_der),
  not_after: config.not_after
}
```

If `Registry.fetch/1` returns `:error` for an unknown algorithm string, the key is dropped with a `:unknown_algorithm` failure reason — same pattern as the existing decryption-failure drop.

### Consumer changes

`ResponseBuilder.sign_tbs/2` becomes:

```elixir
defp sign_tbs(tbs, %{signer: signer_mod, private_key: priv}) do
  signature = signer_mod.sign(tbs, priv)
  {signer_mod.algorithm_identifier_der(), signature}
end
```

One clause. No algorithm string dispatch. The per-algorithm DER blob module attributes disappear from `ResponseBuilder` entirely.

`DerGenerator.sign_tbs/2` becomes the same:

```elixir
defp sign_tbs(tbs, %{signer: signer_mod, private_key: priv}) do
  signature = signer_mod.sign(tbs, priv)
  {signer_mod.algorithm_identifier_der(), signature}
end
```

And `DerGenerator.sig_alg_identifier/1` can be deleted — the signer module owns that now.

### Compatibility + tests

The `signing_key` map shape changes (adds `signer`, `private_key` is now decoded not raw). This is entirely internal — no callers outside `SigningKeyStore`, `ResponseBuilder`, and `DerGenerator` touch these fields. Migration is straightforward:

1. Add the Signer behaviour + concrete modules (no callers yet)
2. Add the Registry
3. Update `SigningKeyStore.load_keys/1` to resolve + cache the signer module + decoded key
4. Update `ResponseBuilder.sign_tbs/2` and `DerGenerator.sign_tbs/2` to use the cached module
5. Delete the old algorithm-string dispatch clauses + DER blob module attributes
6. Run all tests — the 125 existing tests should all still pass unchanged (the external contracts of `build/4` and `generate/2` don't change)

New tests:

- Unit tests for each Signer module: `decode_private_key/1` round-trip, `sign/2` produces bytes verifiable by `:public_key.verify/4`, `algorithm_identifier_der/0` returns the expected OID
- Registry fetch test: known strings return modules, unknown returns `:error`
- SigningKeyStore test: unknown algorithm string is dropped at load time with `:unknown_algorithm` failure reason

### Followup seam documented

Add a comment in `Registry.@mapping` saying: "To add a new signer: create the module under `PkiValidation.Crypto.Signer.*` implementing the behaviour, add a line here, add the string to `SigningKeyConfig.@valid_algorithms`." Three-step developer experience locked in.

## Migration strategy

Both parts land in a **single feature branch** (`feat/validation-followups`) with **two commits**:

1. **Observability first** — smaller, lower risk, provides debugging visibility during the refactor. If the signer refactor causes any load-time issues, the new `/health` endpoint surfaces them immediately.
2. **Signer behaviour extraction** — bigger, riskier, but all the existing tests act as regression guards. The openssl interop tests in particular will catch any wire-format regression introduced by the refactor.

## Out of scope (deferred to separate work)

- **PQC signer modules** (ML-DSA, SLH-DSA, KAZ-SIGN) — the behaviour and registry are the pre-requisite. Actually wiring the PQC NIFs is a separate task that can proceed once this lands.
- **CRL cache read path** — still populates but never reads. Separate follow-up.
- **CRL `authorityKeyIdentifier` extension** — needed for signer rotation. Separate follow-up.
- **RFC 5019 §6.2 cache headers** — `Last-Modified` / `Expires`. Separate follow-up.
- **`issuer_name_hash` column decision** — currently dead weight. Separate follow-up.
- **Drop `/ocsp/der` body cap from 1MB to 8KB** — separate follow-up.

## Test plan

Before merge:
- [ ] All 125 baseline tests still pass
- [ ] New observability tests pass (~5)
- [ ] New signer unit tests pass (~8: 2 per signer module × 4 modules, roughly)
- [ ] Registry tests pass (~2)
- [ ] `mix format --check-formatted` clean
- [ ] `mix test --include interop` still passes (OpenSSL round-trip) — critical: the refactor must not regress wire format

Target: ~140 tests total after both parts land.
