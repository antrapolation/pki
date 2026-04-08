# PQC Certificate Issuance Design

**Date:** 2026-04-08
**Status:** Approved (ready for implementation planning)
**Branch:** `feat/pqc-cert-issuance` (to be created from `main` after spec lands)
**Predecessor PRs:** [#4 RFC 6960/5280/5019 compliance](https://vcs.antrapol.tech:3800/Incubator/pki/pulls/4) (merged), [#5 Signer behaviour + observability](https://vcs.antrapol.tech:3800/Incubator/pki/pulls/5) (merged)

## Goal

Make the CA ceremony issue **real RFC 5280 X.509 DER certificates** for three PQC algorithms — **ML-DSA-65**, **SLH-DSA-SHA2-128s**, and **KAZ-SIGN-128** — replacing the current broken state where the KAZ-SIGN cert path produces a non-standard JSON wrapper and the ML-DSA / SLH-DSA paths aren't wired to ceremony cert signing at all.

This PR is **issuance-only** and **self-signed root only**. Sub-issuer ceremonies, cross-algorithm chains, validation-side OCSP/CRL signing for PQC certs, and the CA → validation provisioning path are explicitly deferred to follow-up specs.

After this PR lands, an admin running a CA bootstrap ceremony with any of the three in-scope PQC algorithms gets a real DER certificate that:

- Round-trips through `:public_key.pkix_decode_cert/2` without raising
- Is parseable by `openssl x509 -inform DER -in cert.der -text -noout`
- For ML-DSA-65 / SLH-DSA-SHA2-128s: passes `openssl verify -CAfile cert.pem cert.pem` (openssl ≥ 3.5)
- For KAZ-SIGN-128: passes a self-verify roundtrip through our own NIF (openssl can't verify the private Malaysian OID)

This is a no-regret move regardless of broader strategic decisions about KAZ-SIGN's role in the product. Real X.509 DER is strictly better than the current JSON hack for every conceivable consumer.

## Decisions captured during brainstorming

The brainstorming session locked in six pivotal decisions. They drive everything that follows.

| # | Question | Decision |
|---|---|---|
| Q1 | Who consumes the certificates this CA issues? | **Standard PKI clients** — browsers, openssl, Java TLS, Go TLS, mTLS endpoints. Certs MUST be RFC 5280 X.509 DER with registered OIDs that off-the-shelf tools recognize. |
| Q2 | Where does KAZ-SIGN fit given Q1? | **KAZ-SIGN issues real X.509 DER certs in this PR.** Standard openssl/browser interop is a deliberate non-goal — KAZ-SIGN's private Malaysian OID isn't recognized by off-the-shelf tools, and verifier tooling is a separate engineering track in the upstream PQC-KAZ repo (the `kaz-pqc-jcajce-v2.0/` Java JCA provider already exists; a custom openssl provider does not). The CA's job is to emit valid certs; verification lives elsewhere. |
| Q3 | What's the scope vertical? | **Issuance only** (Option A). No OCSP/CRL changes. No validation-side PQC signing. No CA → validation provisioning path. ~1 PR. |
| Q4 | Which algorithms in this first PR? | **3 algorithms — ML-DSA-65, SLH-DSA-SHA2-128s, KAZ-SIGN-128.** One representative per family. The remaining 8 PQC parameter sets (ML-DSA-44/87, the other 5 SLH-DSA-SHA2 variants, KAZ-SIGN-192/256) are mechanical follow-up additions in separate PRs. |
| Q5 | Cert hierarchy scope? | **Self-signed root only.** No sub-issuer signing. The current `do_sign_kaz/7` JSON-hack code path in `certificate_signing.ex` survives this PR untouched — sub-issuer PQC signing is a follow-up PR with its own design. |
| Q-Cross | KAZ-SIGN cross-impl verification gate? | **Defer.** Self-verify via our own NIF + structural openssl parse is the test gate for KAZ-SIGN. Java JCA cross-check is rejected (project explicitly avoids JRuby/Java loading latency). Rust-binding cross-check is a useful future hardening but not in this PR. |

## Architecture overview

One new leaf module in `pki_crypto`, two thin call-site changes in `pki_ca_engine`, a quarantine pass on the broken KAZ-SIGN scaffold, and a small dep cleanup. Nothing invents new abstractions; the cert builder slots into the existing `PkiCrypto.Algorithm` protocol as a pure client.

```
                           pki_crypto
                           ──────────
┌─────────────────────────────────────────────────────────┐
│  PkiCrypto.X509.PqcCertBuilder            (NEW, leaf)    │
│  ───────────────────────────                             │
│  • build_self_signed(opts) ::                            │
│      {:ok, cert_der} | {:error, reason}                  │
│                                                          │
│  • Authors TBSCertificate via :public_key.der_encode    │
│    with correct AlgorithmIdentifier for the given alg   │
│  • Encodes SubjectPublicKeyInfo with raw PQC pubkey     │
│  • Calls PkiCrypto.Algorithm.sign/3 on the TBS DER      │
│  • Assembles Certificate {tbs, sigAlg, signature}       │
│  • Depends on: :public_key, PkiCrypto.Algorithm,         │
│                PkiCrypto.X509.OID, X509 library         │
└─────────────────────────────────────────────────────────┘
              │
              │  used by
              ▼
┌─────────────────────────────────────────────────────────┐
│  PkiCrypto.X509.OID                        (NEW, tiny)   │
│  ───────────────────                                     │
│  • algorithm_identifier(name) ::                         │
│      {:ok, {:AlgorithmIdentifier, oid_tuple, params}}    │
│  • algorithms() :: [String.t()]                          │
│  • pqc_algorithm?(name) :: boolean                       │
│  • Single source of truth for algo → OID mapping         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  PkiCrypto.Signing.KazSign{128,192,256}     (FIX in place)│
│  ──────────────────────────                              │
│  • Dep on :kaz_sign declared in pki_crypto/mix.exs      │
│  • sign/3 uses KazSign.sign_detached/3 with right args  │
│  • verify/4 uses KazSign.verify_detached/4              │
│  • generate_keypair/1 unchanged (already correct)       │
└─────────────────────────────────────────────────────────┘

                           pki_ca_engine
                           ─────────────
┌─────────────────────────────────────────────────────────┐
│  ceremony_orchestrator.ex                  (MODIFIED)    │
│  ────────────────────────                                │
│  • generate_self_signed/4 PQC branch replaced           │
│  • Now calls PkiCrypto.X509.PqcCertBuilder              │
│  • KazSign.self_sign/5 dead call removed                │
│  • Classical RSA/ECC path unchanged                     │
│  • generate_csr/4 (sub-issuer CSR) UNTOUCHED            │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  certificate_signing.ex                   (UNTOUCHED)    │
│  ──────────────────────                                  │
│  • do_sign_kaz/7 JSON hack survives this PR             │
│  • Sub-issuer PQC signing is out of scope per Q5        │
│  • Will be replaced in a follow-up PR with build_       │
│    signed_by/2                                           │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  mix.exs                                  (MODIFIED)     │
│  ───────                                                 │
│  • :ap_java_crypto dep DELETED (zero call sites)        │
│  • :kaz_sign dep path uses Path.expand + env override   │
└─────────────────────────────────────────────────────────┘
```

### Why each piece lives where it does

**The new cert builder lives in `pki_crypto`, not `pki_ca_engine`.** Because `pki_crypto`'s test suite runs successfully on `mix test`, while `pki_ca_engine`'s test suite currently can't start (`{:not_running, :ap_java_crypto}` blocker, removed in this PR). All the hard logic is unit-testable from the `pki_crypto` layer; `pki_ca_engine` becomes a thin caller.

**The `OID` module is its own file** instead of being inlined. Because `pki_validation` will need the same algorithm → OID mapping when it grows PQC OCSP/CRL signing in a follow-up PR. One source of truth now, reused later.

**No new abstraction at the protocol level.** `PkiCrypto.Algorithm` already has `sign/3` + `identifier/1`. The cert builder just calls them. No new behaviours, no new protocols, no new registries — consistent with existing pki_crypto style.

**KAZ-SIGN is explicitly un-parked** in this PR. The brainstorming Q2 outcome accepted that KAZ-SIGN won't have standard openssl/browser interop, but the cert structure itself can still be RFC-compliant X.509 DER. The cost of including KAZ-SIGN alongside ML-DSA / SLH-DSA is small (one more entry in the OID map, one more set of tests, the scaffold bug fix that needs to happen anyway).

## The `PqcCertBuilder` module

### Public API

One function, one purpose:

```elixir
defmodule PkiCrypto.X509.PqcCertBuilder do
  @moduledoc """
  Builds RFC 5280 X.509 DER certificates for PQC signing algorithms.

  This is a PQC-specific builder. Classical (RSA, ECC) certificates
  continue to be built through the existing `X509` Elixir library path
  in `pki_ca_engine/certificate_signing.ex`. The two paths coexist
  because the `X509` library has no notion of NIST FIPS 204/205 or
  Malaysian KAZ-SIGN OIDs — rather than retrofit a classical library,
  we add a parallel PQC-native builder.

  Sub-issuer signing (`build_signed_by/2`) is deliberately out of scope
  for this module's first cut. See the follow-up spec when sub-issuer
  ceremonies need real X.509 output.
  """

  @type opts :: [
    algorithm: String.t(),
    private_key: binary(),
    public_key: binary(),
    subject_dn: String.t(),
    serial: pos_integer(),
    not_before: DateTime.t(),
    not_after: DateTime.t(),
    extensions: keyword()
  ]

  @doc """
  Build a self-signed X.509 root CA certificate with a PQC signature.

  Returns DER-encoded Certificate bytes. Use `:public_key.pem_encode/1`
  with `[{:Certificate, der, :not_encrypted}]` to wrap in PEM if needed.
  """
  @spec build_self_signed(opts()) :: {:ok, binary()} | {:error, term()}
  def build_self_signed(opts)
end
```

### Required and optional inputs

**Required (raise `:missing_required_option` if absent):**

- `:algorithm` — name string registered in `PkiCrypto.X509.OID.@algorithm_oids`
- `:private_key` — raw private key bytes as returned by `PkiCrypto.Algorithm.generate_keypair/1`
- `:public_key` — raw public key bytes as returned by `PkiCrypto.Algorithm.generate_keypair/1`
- `:subject_dn` — RFC 4514 string like `"CN=Test Root CA,O=Antrapol,C=MY"`. Becomes both subject AND issuer (self-signed).

**Optional with sensible defaults:**

- `:serial` — random positive 64-bit integer if absent
- `:not_before` — `DateTime.utc_now/0` if absent
- `:not_after` — `not_before + 25 years` if absent (matches the existing `ceremony_orchestrator.ex` 25-year root validity)
- `:extensions` — keyword list of *additional* extensions to include alongside the default root CA set; appended to defaults, not replacing them

### Default extensions for self-signed roots

A self-signed root cert is useless without these. They're not optional — `openssl verify` will reject the cert without `basicConstraints` and `keyUsage`. We provide them automatically:

| Extension | OID | Critical | Value |
|---|---|---|---|
| `basicConstraints` | `2.5.29.19` | true | `cA: true`, no pathLenConstraint |
| `keyUsage` | `2.5.29.15` | true | bits: `keyCertSign + cRLSign` |
| `subjectKeyIdentifier` | `2.5.29.14` | false | SHA-1 of the raw public key bytes (RFC 5280 §4.2.1.2 method 1) |
| `authorityKeyIdentifier` | `2.5.29.35` | false | Same as SKI (self-signed implies AKI = SKI) |

### Error tuples

| Error | Meaning |
|---|---|
| `{:error, :unknown_algorithm}` | `:algorithm` value not in the OID registry |
| `{:error, :invalid_dn}` | `:subject_dn` failed to parse via `X509.RDNSequence.new/1` |
| `{:error, :invalid_validity}` | `not_after <= not_before` |
| `{:error, {:signing_failed, reason}}` | The underlying `PkiCrypto.Algorithm.sign/3` returned an error |
| `{:error, {:encoding_failed, reason}}` | ASN.1 encoding of the TBS or final Certificate raised |

### Return shape

`{:ok, cert_der}` returns raw DER bytes. Callers wrap in PEM if needed:

```elixir
cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
```

This keeps the module focused on ASN.1 / X.509 concerns and leaves transcoding to callers, matching how `pki_validation`'s `DerGenerator` returns DER and the router wraps to PEM.

### New `pki_crypto` dependencies

Two added to `pki_crypto/mix.exs`:

```elixir
defp deps do
  [
    {:keyx, path: "../keyx", override: true},
    {:uniq, "~> 0.6"},
    {:pki_oqs_nif, path: "../pki_oqs_nif"},
    {:x509, path: "../x509", override: true},  # NEW
    {:kaz_sign, path: kaz_sign_path()}         # NEW
  ]
end

defp kaz_sign_path do
  System.get_env("KAZ_SIGN_PATH") ||
    Path.expand("~/Workspace/PQC-KAZ/SIGN/bindings/elixir")
end
```

The `x509` library is used strictly for helpers — DN parsing via `X509.RDNSequence.new/1` and extension construction via `X509.Certificate.Extension.{basic_constraints, key_usage, subject_key_identifier}/*`. The actual TBS encoding, PQC signing, and final cert assembly all stay in the new `PqcCertBuilder` module. The X509 library's own cert signing path (`X509.Certificate.self_signed/3`) uses only classical `:public_key.sign/3` and cannot be extended to PQC signers — so we don't use its signing entry point at all.

## Internals

### `PkiCrypto.X509.OID` mapping module

Tiny, focused, single source of truth for algorithm name → AlgorithmIdentifier:

```elixir
defmodule PkiCrypto.X509.OID do
  @moduledoc """
  Maps algorithm name strings to their X.509 AlgorithmIdentifier records.

  Single source of truth for every signing algorithm this project emits
  in X.509 structures. Any module that needs to produce a signed artifact
  (cert, CRL, OCSP response) consults this module — never hard-codes the
  OID bytes inline.

  The returned record is shaped for use with `:public_key.der_encode(...)`
  on types like `:Certificate`, `:TBSCertificate`, `:TBSCertList`, which
  accept the typed `{:AlgorithmIdentifier, oid, params}` form.
  """

  @type oid_tuple :: tuple()
  @type algorithm_identifier :: {:AlgorithmIdentifier, oid_tuple(), term()}

  # OID definitions:
  #
  # NIST FIPS 204 (ML-DSA):
  #   id-ml-dsa-65          2.16.840.1.101.3.4.3.18
  #
  # NIST FIPS 205 (SLH-DSA, SHA2 pure variants):
  #   id-slh-dsa-sha2-128s  2.16.840.1.101.3.4.3.20
  #
  # KAZ-SIGN (Malaysian PQC, private enterprise OID arc):
  #   kaz-sign-128          1.3.6.1.4.1.62395.1.2.1

  @algorithm_oids %{
    "ML-DSA-65"         => {2, 16, 840, 1, 101, 3, 4, 3, 18},
    "SLH-DSA-SHA2-128s" => {2, 16, 840, 1, 101, 3, 4, 3, 20},
    "KAZ-SIGN-128"      => {1, 3, 6, 1, 4, 1, 62_395, 1, 2, 1}
  }

  @spec algorithm_identifier(String.t()) ::
          {:ok, algorithm_identifier()} | {:error, :unknown_algorithm}
  def algorithm_identifier(name) do
    case Map.fetch(@algorithm_oids, name) do
      {:ok, oid} -> {:ok, {:AlgorithmIdentifier, oid, :asn1_NOVALUE}}
      :error -> {:error, :unknown_algorithm}
    end
  end

  @spec algorithms() :: [String.t()]
  def algorithms, do: Map.keys(@algorithm_oids)

  @spec pqc_algorithm?(String.t()) :: boolean()
  def pqc_algorithm?(name), do: name in algorithms()
end
```

**Three entries for this PR.** Adding the other 8 PQC parameter sets is a one-line-per-algorithm follow-up.

**`:asn1_NOVALUE` params for all three.** NIST FIPS 204 and 205 specify absent parameters for ML-DSA / SLH-DSA AlgorithmIdentifiers. The KAZ-SIGN 2.0 spec also uses no params (per `kaz-pqc-jcajce-v2.0/src/main/java/com/antrapol/kaz/KAZOIDConstant.java`).

**Three separate registries acknowledged as duplication debt.** `PkiCrypto.Registry`, `PkiCrypto.X509.OID`, and `PkiValidation.Crypto.Signer.Registry` all exist. Each serves a distinct purpose (algorithm structs vs OID-for-encoding vs cached-signer-modules-for-validation), so merging them is a separate refactor. Documented in followups.

### TBS construction flow

The `build_self_signed/1` implementation walks seven steps from input keyword list to DER output:

```
1. Validate + normalize inputs
   • algorithm in OID registry?     → {:error, :unknown_algorithm}
   • subject_dn parses?             → {:error, :invalid_dn}
   • not_after > not_before?        → {:error, :invalid_validity}

2. Build AlgorithmIdentifier record
   {:ok, sig_alg} = PkiCrypto.X509.OID.algorithm_identifier(name)
   Used in TWO places: TBS.signature AND outer
   Certificate.signatureAlgorithm. They MUST be byte-identical.

3. Build SubjectPublicKeyInfo
   spki = {:SubjectPublicKeyInfo, sig_alg, public_key_bytes}
   Raw PQC pubkey bytes go directly into the BIT STRING field.
   No algorithm-specific wrapping.

4. Build extensions list
   • basicConstraints  cA:TRUE                  [CRITICAL]
   • keyUsage          keyCertSign + cRLSign    [CRITICAL]
   • subjectKeyIdentifier  SHA-1 of pubkey      [non-critical]
   • authorityKeyIdentifier  same as SKI        [non-critical]

5. Assemble TBSCertificate record
   tbs = {:TBSCertificate, :v3, serial, sig_alg, issuer_rdn,
          {:Validity, not_before, not_after}, subject_rdn,
          spki, :asn1_NOVALUE, :asn1_NOVALUE, extensions}
   tbs_der = :public_key.der_encode(:TBSCertificate, tbs)

6. Sign
   algo_struct = PkiCrypto.Registry.get(name)
   {:ok, sig_bytes} = PkiCrypto.Algorithm.sign(algo_struct,
                                                private_key, tbs_der)

7. Assemble Certificate + DER encode
   cert = {:Certificate, tbs, sig_alg, sig_bytes}
   cert_der = :public_key.der_encode(:Certificate, cert)
   {:ok, cert_der}
```

### Encoder strategy: the `:plain` form

Elixir's `:public_key` module offers two encoder schemas. Using the wrong one breaks PQC.

| Schema | Behaviour on PQC |
|---|---|
| `:public_key.der_encode(:OTPCertificate, ...)` | Tries to type-parse the `SubjectPublicKeyInfo` into algorithm-specific records. **Rejects or mangles unknown OIDs.** |
| `:public_key.der_encode(:Certificate, ...)` | Plain PKIX schema where `subjectPublicKey` is an opaque `BIT STRING`. **Passes raw bytes through without algorithm-specific parsing.** |

**We use the `:Certificate` plain form.** Same strategy as `pki_validation/lib/pki_validation/crl/der_generator.ex`, which I've already empirically verified works with PQC OIDs in the `signatureAlgorithm` field of `:TBSCertList`. The `:Certificate` / `:TBSCertificate` types should behave identically (same encoder family, same handling of unknown OIDs in nested AlgorithmIdentifier fields), but I haven't verified the SPKI bitstring path specifically — that's risk #1 below.

### `pki_crypto` KAZ-SIGN scaffold fix

Three specific changes to `src/pki_crypto/lib/pki_crypto/signing/kaz_sign.ex`. The current code has the right structure but two real bugs: it calls a function with wrong argument order and uses the message-recovery variant where the detached variant is needed.

**Change 1 — declare the `:kaz_sign` dep in `pki_crypto/mix.exs`:** (covered above in "New dependencies")

**Change 2 — fix `sign/3` arg order and use detached variant** (all three KazSign protocol impls):

```elixir
# BEFORE (kaz_sign.ex line 23, repeated for 192/256)
def sign(_, private_key, data), do: KazSign.sign(128, private_key, data)
                                            #   ^^^ wrong: KazSign.sign is (level, message, private_key)
                                            #   ^^^ also wrong: this is the message-recovery variant

# AFTER
def sign(_, private_key, data), do: KazSign.sign_detached(128, data, private_key)
                                            #   ^^^ correct: detached variant for X.509 / OCSP / CRL signing
                                            #   ^^^ arg order matches KazSign.sign_detached(level, data, secret_key)
```

**Change 3 — fix `verify/4` arg order, use detached variant, and map result shape:**

```elixir
# BEFORE
def verify(_, public_key, signature, data),
  do: KazSign.verify(128, public_key, signature, data)
      #   ^^^ wrong: KazSign.verify is 3-arg (level, signature, public_key) for message-recovery

# AFTER — map KazSign.verify_detached result shape to PkiCrypto.Algorithm contract
def verify(_, public_key, signature, data) do
  case KazSign.verify_detached(128, data, signature, public_key) do
    {:ok, true} -> :ok
    {:ok, false} -> {:error, :invalid_signature}
    {:error, _} = err -> err
  end
end
```

Same fixes applied to all three KazSign levels (128, 192, 256).

### Stale count assertions in `algorithm_integration_test.exs`

```elixir
# BEFORE
test "registry contains expected total count" do
  all = Registry.all()
  # 12 signing + 1 KEM = 13
  assert map_size(all) == 13
end

test "signing_algorithms returns only signing type" do
  signing = Registry.signing_algorithms()
  assert map_size(signing) == 12
  ...
end

# AFTER
test "registry contains expected total count" do
  all = Registry.all()
  # 15 signing + 1 KEM = 16
  #   Signing: 3 classical (RSA-4096, ECC-P256, ECC-P384)
  #            + 3 KAZ-SIGN levels
  #            + 3 ML-DSA parameter sets
  #            + 6 SLH-DSA-SHA2 parameter sets
  #   KEM:     1 ECDH-P256
  assert map_size(all) == 16
end

test "signing_algorithms returns only signing type" do
  signing = Registry.signing_algorithms()
  assert map_size(signing) == 15
  ...
end
```

The third pre-existing failure — `RegistryTest "every registered algorithm can generate a keypair"` — goes green automatically once Change 1 above lands (`:kaz_sign` dep declared, NIF loadable). No test changes needed.

## `pki_ca_engine` integration

### `mix.exs` — two changes

```diff
  defp deps do
    [
      ...
      {:pki_platform_engine, path: "../pki_platform_engine"},
-     {:ap_java_crypto, path: "../ap_java_crypto"},
-     {:kaz_sign, path: "../../../PQC-KAZ/SIGN/bindings/elixir", optional: true}
+     {:kaz_sign, path: kaz_sign_path()}
    ]
  end

+ defp kaz_sign_path do
+   System.get_env("KAZ_SIGN_PATH") ||
+     Path.expand("~/Workspace/PQC-KAZ/SIGN/bindings/elixir")
+ end
```

**Why delete `:ap_java_crypto`:** Zero call sites in `pki_ca_engine/lib/`, `test/`, or `config/`. Exhaustive grep returns only the one declaration in `mix.exs` (and references in `erl_crash.dump` which is a leftover from a previous crash). The dep is an OTP application that pulls in `ex_jruby_port`, which fails to start JRuby in test env, which produces `{:not_running, :ap_java_crypto}` and prevents `pki_ca_engine`'s test suite from starting at all. Removing the edge unblocks `mix test` with zero functional impact.

**Why fix the `:kaz_sign` path:** The current relative path `../../../PQC-KAZ/SIGN/bindings/elixir` resolves correctly in the main checkout (`~/Workspace/pki/`) but resolves into `~/Workspace/pki/.worktrees/PQC-KAZ` (nonexistent) when `pki_ca_engine`'s `mix.exs` is processed from a worktree. Using `Path.expand("~/Workspace/PQC-KAZ/...")` makes the path independent of the working directory. Must match `pki_crypto/mix.exs`'s identical helper exactly — Mix rejects diverging sub-dependency paths.

### `ceremony_orchestrator.ex` — fix `generate_self_signed/4`

```elixir
# BEFORE
defp generate_self_signed(algorithm, private_key, public_key, subject_dn) do
  case kaz_sign_level(algorithm) do
    {:ok, level} ->
      with :ok <- KazSign.init(level),
           {:ok, csr_der} <- KazSign.generate_csr(level, private_key, public_key, subject_dn),
           {:ok, cert_der} <- KazSign.self_sign(level, private_key, public_key, csr_der, 365 * 25) do
        # KazSign.self_sign/5 DOES NOT EXIST — crashes UndefinedFunctionError at runtime
        cert_pem = pem_encode("CERTIFICATE", cert_der)
        {:ok, cert_der, cert_pem}
      end

    :error ->
      # classical X509 library path (works for RSA/ECC, would also fail for ML-DSA/SLH-DSA)
      try do
        native_key = decode_private_key(private_key)
        root_cert = X509.Certificate.self_signed(native_key, subject_dn,
          template: :root_ca, hash: :sha256, serial: {:random, 8}, validity: 365 * 25)
        cert_der = X509.Certificate.to_der(root_cert)
        cert_pem = X509.Certificate.to_pem(root_cert)
        {:ok, cert_der, cert_pem}
      rescue
        e -> {:error, e}
      end
  end
end

# AFTER
defp generate_self_signed(algorithm, private_key, public_key, subject_dn) do
  if PkiCrypto.X509.OID.pqc_algorithm?(algorithm) do
    # PQC path: delegate to the new builder. All in-scope PQC algorithms
    # (ML-DSA-65, SLH-DSA-SHA2-128s, KAZ-SIGN-128) go through this branch.
    case PkiCrypto.X509.PqcCertBuilder.build_self_signed(
           algorithm: algorithm,
           private_key: private_key,
           public_key: public_key,
           subject_dn: subject_dn,
           not_after: DateTime.add(DateTime.utc_now(), 25 * 365 * 86_400, :second)
         ) do
      {:ok, cert_der} ->
        cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
        {:ok, cert_der, cert_pem}

      {:error, _} = err ->
        err
    end
  else
    # Classical RSA/ECC path via X509 library — UNCHANGED
    try do
      native_key = decode_private_key(private_key)
      root_cert = X509.Certificate.self_signed(native_key, subject_dn,
        template: :root_ca, hash: :sha256, serial: {:random, 8}, validity: 365 * 25)
      cert_der = X509.Certificate.to_der(root_cert)
      cert_pem = X509.Certificate.to_pem(root_cert)
      {:ok, cert_der, cert_pem}
    rescue
      e -> {:error, e}
    end
  end
end
```

**What stays untouched:**

- `generate_csr/4` — the sub-issuer-CSR code path. Calls `KazSign.generate_csr/4` (which DOES exist in the binding lib) and the X509 library for classical. Sub-issuer ceremonies are out of scope per Q5.
- `kaz_sign_level/1` helper — still used by `generate_csr/4`, stays.
- All ceremony / threshold / share-distribution / auditor witness code — none of it touches cert signing.

### `certificate_signing.ex` — no changes

`do_sign_kaz/7` is the **sub-issuer** signing path (CSR → issuer-signed cert), not the self-signed root path. The self-signed path is in `ceremony_orchestrator.ex` (covered above). Sub-issuer signing is out of scope per Q5, so `certificate_signing.ex` is **completely untouched** in this PR.

The JSON-wrapper hack stays alive and dormant. Anyone exercising the sub-issuer KAZ-SIGN path (nobody, AFAIK) continues to get the broken JSON output. The follow-up PR will add `PqcCertBuilder.build_signed_by/2` and refactor `do_sign_kaz/7` and friends out of existence.

### `pki_ca_engine` summary table

| File | Change | Lines added | Lines removed |
|---|---|---|---|
| `mix.exs` | Remove ap_java_crypto; fix kaz_sign path | +6 | -2 |
| `lib/pki_ca_engine/ceremony_orchestrator.ex` | Replace PQC branch in `generate_self_signed/4` | +15 | -10 |
| `lib/pki_ca_engine/certificate_signing.ex` | **No changes** | 0 | 0 |

Total: 2 files, ~30 lines diff. Well under "needs its own PR."

## Test strategy

### Test layers

**Layer 1 — `pki_crypto` (the heavy lifting):**

| File | Status | Purpose |
|---|---|---|
| `test/pki_crypto/x509/pqc_cert_builder_test.exs` | NEW | Builder unit tests — one describe block per algorithm × 4 gates |
| `test/pki_crypto/x509/oid_test.exs` | NEW | OID mapping — happy/unknown/listing/membership |
| `test/pki_crypto/signing/kaz_sign_test.exs` | NEW | Scaffold-fix regression guards (sign+verify roundtrip per level) |
| `test/pki_crypto/signing/ml_dsa_test.exs` | NEW | First protocol-layer coverage (PkiOqsNif has its own tests) |
| `test/pki_crypto/signing/slh_dsa_test.exs` | NEW | First protocol-layer coverage |
| `test/pki_crypto/algorithm_integration_test.exs` | MODIFIED | Update stale `12/13` counts to `15/16` with comment |
| `test/support/pqc_cert_test_helpers.ex` | NEW | Shared test plumbing |

**Layer 2 — `pki_ca_engine` (integration, conditional on test env):**

| File | Status | Purpose |
|---|---|---|
| `test/pki_ca_engine/ceremony_orchestrator_pqc_test.exs` | NEW (conditional) | Integration test for the modified `generate_self_signed/4` PQC branch |

Only added if `pki_ca_engine`'s test suite can start after the `ap_java_crypto` removal. Otherwise documented as deferred.

**Layer 3 — `pki_validation`:** No changes. Baseline 154 tests stays 154.

### Test gates per algorithm

| Gate | ML-DSA-65 | SLH-DSA-SHA2-128s | KAZ-SIGN-128 |
|---|---|---|---|
| **1: structural** — round-trip through `:public_key.pkix_decode_cert/2` | ✓ | ✓ | ✓ |
| **2: openssl parse** — `openssl x509 -text -noout` exits 0 + correct OID/algo string in output | ✓ | ✓ | ✓ (parses; OID shows as `1.3.6.1.4.1.62395.1.2.1`) |
| **3: openssl verify** — `openssl verify -CAfile cert.pem cert.pem` exits 0 | ✓ (gates on openssl ≥ 3.5) | ✓ (gates on openssl ≥ 3.5) | **SKIP** (private OID, openssl can't recognize) |
| **4: self-verify via NIF** — extract TBS + signature, call `PkiCrypto.Algorithm.verify/4` | ✓ | ✓ | ✓ (the only correctness gate available) |

### Shared test helpers

One new module: `test/support/pqc_cert_test_helpers.ex`. Public functions:

```elixir
defmodule PkiCrypto.PqcCertTestHelpers do
  @moduledoc false

  # Build a cert with sensible defaults; caller overrides only what they care about.
  def build_test_cert(algorithm_name, opts \\ [])

  # DER → PEM → temp file. Returns pem_path; on_exit cleanup is the caller's job.
  def write_cert_pem(cert_der)

  # `openssl x509 -text -noout` on a pem path. Returns {output, exit_code}.
  def openssl_x509_text(pem_path)

  # `openssl verify -CAfile X X`. Returns exit_code.
  def openssl_verify(pem_path)

  # openssl version detection. Returns {:ok, version_string} or :not_installed.
  def openssl_version()

  # Boolean: openssl >= 3.5.0?
  def openssl_supports_pqc_verify?()

  # Parse a cert and return {:ok, %{tbs_der, signature, public_key}} for self-verify.
  def extract_tbs_sig_pubkey(cert_der)
end
```

### openssl version skip logic

Tests use module-level skip via `setup_all`:

```elixir
setup_all do
  case H.openssl_version() do
    {:ok, version} ->
      cond do
        Version.compare(version, "3.5.0") in [:eq, :gt] ->
          {:ok, openssl_can_verify_pqc: true}

        true ->
          IO.puts(:stderr, "WARNING: openssl #{version} cannot verify ML-DSA / SLH-DSA. " <>
            "Gate 3 will be skipped. Install openssl >= 3.5.0 for full coverage.")
          {:ok, openssl_can_verify_pqc: false}
      end

    :not_installed ->
      {:skip, "openssl CLI required for X.509 cert tests"}
  end
end
```

Tests requiring openssl 3.5+ check the context and skip individually if needed:

```elixir
test "openssl verify accepts the self-signature", %{openssl_can_verify_pqc: ok} do
  if !ok, do: ExUnit.skip("openssl >= 3.5.0 required")
  ...
end
```

KAZ-SIGN tests have NO openssl version dependency — gate 2 only requires that openssl can parse the X.509 structure, which any modern openssl handles regardless of whether it knows the signature algorithm OID.

### Test count expectations

| Package | Baseline (clean main) | Expected after PR | Delta |
|---|---|---|---|
| `pki_crypto` | 131 tests, **3 failing** | ~155 tests, **0 failing** | +24 new, 3 going green |
| `pki_validation` | 154 tests, 0 failing | 154 tests, 0 failing | No change |
| `pki_ca_engine` | **Cannot start** | At least starts after ap_java_crypto removal. Integration tests added if env allows. | Pending R3 outcome (see risks below) |

The 3 pre-existing failures going green:

1. `RegistryTest "every registered algorithm can generate a keypair"` — fixed by Section "KAZ-SIGN scaffold fix" (add dep, fix arg order, use detached variant)
2. `AlgorithmIntegrationTest "registry contains expected total count"` — fixed by stale count update
3. `AlgorithmIntegrationTest "signing_algorithms returns only signing type"` — same fix

## Scope, risks, and followups

### In scope (exhaustive)

**New code in `pki_crypto`:**
- `lib/pki_crypto/x509/pqc_cert_builder.ex` — `build_self_signed/1`
- `lib/pki_crypto/x509/oid.ex` — algorithm name → OID mapping
- `test/support/pqc_cert_test_helpers.ex` — shared test plumbing
- 6 new test files (oid, pqc_cert_builder, kaz_sign, ml_dsa, slh_dsa, plus the helpers being exercised)

**Modified files in `pki_crypto`:**
- `mix.exs` — add `:x509` and `:kaz_sign` deps with `Path.expand` + env var pattern
- `lib/pki_crypto/signing/kaz_sign.ex` — fix arg order, use `sign_detached`, fix verify result mapping
- `test/pki_crypto/algorithm_integration_test.exs` — fix stale count assertions

**Modified files in `pki_ca_engine`:**
- `mix.exs` — remove `:ap_java_crypto`, fix `:kaz_sign` path
- `lib/pki_ca_engine/ceremony_orchestrator.ex` — replace PQC branch in `generate_self_signed/4`

**Conditional in `pki_ca_engine`:**
- `test/pki_ca_engine/ceremony_orchestrator_pqc_test.exs` — integration test if env allows

**Algorithm coverage:** ML-DSA-65, SLH-DSA-SHA2-128s, KAZ-SIGN-128.
**Cert hierarchy coverage:** Self-signed root only.
**Total diff surface:** ~14 files, ~760 LOC added, ~30 LOC removed.

### Out of scope (explicit non-goals)

| Item | Reason | Followup |
|---|---|---|
| Sub-issuer PQC signing (CSR → issuer-signed cert) | Q5 self-signed-only. The `do_sign_kaz/7` JSON hack survives untouched. | "PQC sub-issuer signing" spec |
| All other PQC parameter sets (ML-DSA-44/87, SLH-DSA SHA2 192s/192f/256s/256f/128f, KAZ-SIGN-192/256) | Q4 chose 3 representative algorithms. Mechanical follow-up. | Trivial follow-up PRs, one per algorithm |
| CA → validation provisioning of delegated signing keys | Q3 issuance-only. Validation has no way to get PQC signing keys from the CA. Pre-existing gap. | High-priority spec — substantial design |
| `pki_validation` PQC OCSP/CRL signing | Depends on the provisioning path above. | Same followup spec |
| CA portal KAZ-SIGN labeling/UX | Not on the table. The algorithm WORKS now after this PR. | Small UX PR if/when management decides |
| `ap_java_crypto` + `ex_jruby_port` package deletion | Removing the dep edge is in scope; deleting the packages requires verifying no other usage. | Cleanup PR. Low priority. |
| Three-registry consolidation | Acknowledged duplication debt. Each serves a distinct purpose. | Quality-of-life refactor spec. Low priority. |
| Hybrid certificate chains (PQC + classical cross-signing) | Same family as sub-issuer signing. Bigger design surface. | Same "PQC sub-issuer signing" spec, possibly extended |
| Custom openssl provider for KAZ-SIGN | Engineering track in PQC-KAZ upstream, not this CA repo. | Out of this team's scope |
| Rust-binding cross-verification gate for KAZ-SIGN | Useful future hardening; deferred per Q-Cross. | Follow-up PR if/when needed |
| `pki_ca_engine` test env stabilization beyond `ap_java_crypto` | Removing ap_java_crypto is the necessary first step. Other gaps documented but not fixed. | Test env setup PR if blockers surface |

### Known risks and mitigation

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | `:public_key.der_encode(:Certificate, ...)` rejects raw PQC SPKI bitstring | Medium | High — would block the whole approach | **First implementation step:** 5-min iex smoke test that encodes a minimal `:Certificate` with a PQC OID and BIT STRING SPKI. **Fallback if it fails:** author a minimal `pki_crypto/asn1/X509.asn1` compiled module (~40 lines) following the same pattern as `pki_validation/asn1/OCSP.asn1`. Cost: ~1 extra day. |
| R2 | openssl 3.5+ doesn't actually verify SLH-DSA-SHA2-128s specifically | Medium | Low — degrades gate 3 to skipped | Empirical check during implementation. If 128s isn't supported, swap to `128f` (same security level, faster keygen, same family). Update the spec and re-run gate 3 against the new variant. |
| R3 | `pki_ca_engine` has additional pre-existing startup failures beyond `ap_java_crypto` | Medium-high | Low — integration tests deferred | If 30 minutes of investigation can fix additional blockers cleanly, include them. If not, document them and ship the PR with `pki_crypto`-layer tests as the only test gate. |
| R4 | `x509` library doesn't have the extension helpers (`X509.Certificate.Extension.basic_constraints/1` etc.) | Low | Low — fall back to manual extension building via `:public_key.der_encode/2` | Verify during implementation. Hand-build if missing. ~2 hours extra. |
| R5 | `KAZ_SIGN_PATH` env var override causes confusing errors when devs override one package's path but not the other's | Low | Medium — hard-to-diagnose mix divergence error | Document in the spec that the env var must be set globally or not at all. Add cross-reference notes in both `mix.exs` files. |
| R6 | KAZ-SIGN's `sign_detached` produces unexpectedly large signatures, breaking test assertions | Very low | Very low — adjust test expectations | 1-line iex empirical check during implementation. |
| R7 | Removing `ap_java_crypto` from `pki_ca_engine`'s mix.exs surfaces an unexpected build dependency | Very low (verified by exhaustive grep) | Medium — would need to revert | If a build error appears unexpectedly, restore the dep and investigate before the PR ships. |

### Followup specs in priority order

After this PR lands, the next design specs to write and execute, in priority order:

1. **CA → validation delegated signer provisioning protocol** (highest priority — unblocks everything PQC-related on the validation side). Substantial design — needs its own brainstorming session covering EKU choices, key wrapping format, rotation flow, audit logging.

2. **Sub-issuer PQC cert signing** (`PqcCertBuilder.build_signed_by/2`, refactor of `certificate_signing.ex::do_sign/6`, deletion of `do_sign_kaz/7` and the JSON hack helpers). Resolves the JSON hack permanently.

3. **`PkiValidation.Crypto.Signer` PQC modules** (`MlDsa65`, `SlhDsaSha2128s`, `KazSign128`). Depends on #1 landing first.

4. **Add the remaining 8 PQC parameter sets** (ML-DSA-44/87, SLH-DSA-SHA2 192s/192f/256s/256f/128f, KAZ-SIGN-192/256). One line per algorithm + tests. Mechanical.

5. **Hybrid certificate chains.** PQC leaf signed by classical root, classical leaf signed by PQC root. Builds on #2.

6. **Three-registry consolidation refactor.** Quality-of-life cleanup.

7. **`ap_java_crypto` + `ex_jruby_port` legacy package deletion.** Orthogonal cleanup.

8. **`pki_ca_engine` test env stabilization.** Force multiplier for everything else.

9. **Rust-binding cross-verification gate for KAZ-SIGN.** Independent-implementation hardening.

### Open questions for management (the strategic ones)

These need product/business input, not engineering tradeoffs:

1. **Is KAZ-SIGN's "primary algorithm" status from the product spec still aspirational, or is it the production goal?** This PR moves KAZ-SIGN from "broken scaffolding" to "issues real X.509 certs", but standard PKI clients still won't verify them. Whether that's acceptable depends on the customer story.
2. **What's the expected verification path for KAZ-SIGN-issued certs in customer environments?** Closed-loop Antrapolation product family? Java consumers via the existing JCA provider? Custom openssl provider distribution? Determines what verification tooling needs to ship alongside the CA.
3. **Is there a target date or compliance deadline for any specific PQC algorithm being "production-ready"?** Affects scope prioritization for the followup PRs.

The current PR is a no-regret move regardless of the answers above — real X.509 is strictly better than the JSON hack.

## Design checkpoint — what the system looks like after this PR

- ✅ Real X.509 DER PQC certs can be issued for ML-DSA-65, SLH-DSA-SHA2-128s, KAZ-SIGN-128 (self-signed roots only)
- ✅ openssl can parse all three; openssl can verify ML-DSA + SLH-DSA; KAZ-SIGN self-verifies through our NIF
- ✅ The `pki_crypto` test suite is green (3 pre-existing failures fixed)
- ✅ The `pki_ca_engine` test suite can at least start (`ap_java_crypto` blocker removed)
- ✅ KAZ-SIGN scaffold bugs are fixed at the source (arg order, dep declaration, detached variant)
- ⏳ Sub-issuer PQC signing still uses the JSON hack (dormant, untouched, follow-up PR)
- ⏳ `pki_validation` has no PQC OCSP/CRL signing (follow-up after provisioning lands)
- ⏳ The remaining 8 PQC parameter sets aren't in `OID.@algorithm_oids` yet (cheap follow-up)
- ⏳ The three-registry duplication is acknowledged debt
