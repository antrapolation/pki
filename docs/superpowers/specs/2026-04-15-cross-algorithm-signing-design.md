# Cross-Algorithm Certificate Signing — Design

**Date:** 2026-04-15
**Status:** Approved — ready for implementation planning
**Scope:** CA engine, validation engine, shared crypto library

## Goal

Enable every combination of issuer and subject algorithm in the CA hierarchy:
classical ↔ classical (today), classical → PQC, PQC → classical, and cross-family
PQC (e.g. ML-DSA → KAZ-SIGN). All certificates become RFC 5280 X.509 v3; the
legacy JSON-wrapper format for KAZ-SIGN is retired. Validation services (OCSP,
CRL) sign in the issuing CA's own algorithm, including PQC.

## Motivation

Real-world PKI migrations depend on classical roots signing PQC subordinates
(common migration pattern) and, for organisations with a PQC trust anchor, PQC
roots signing classical subordinates during the transition. The current code
only supports same-family signing because `X509.CSR.from_pem` cannot parse PQC
CSRs and `KazSign.sign` emits a JSON-wrapped pseudo-certificate that no
classical tooling understands.

Cross-algorithm signing is standard X.509 — `subjectPublicKeyInfo.algorithm`
and `signatureAlgorithm` are independent fields. The blocker is engineering,
not cryptography.

## Non-goals

- **Composite (hybrid) signatures** per `draft-ietf-lamps-pq-composite-sigs`
  are out of scope for v1. Every cert carries a single signature.
- **Backwards compatibility with existing JSON-wrapper KAZ-SIGN certs.** Hard
  cutover; no bridge. Any previously-issued JSON certs are considered test
  artefacts and will be reissued under the new code path.
- **Interoperability with OpenSSL for KAZ-SIGN.** OpenSSL has no KAZ-SIGN OID
  registered, so it will recognise the X.509 structure but reject the
  signature. This is correct behaviour and documented as a limitation.

## Design decisions (locked)

| Decision | Choice | Rationale |
|---|---|---|
| Combinations supported | B + C + D (full matrix) | Complete product, not a partial rollout |
| Cert output format | Standard single-algorithm X.509 | RFC 5280 compliant; composite deferred |
| CSR input format | Standard PKCS#10 everywhere | One parser, one signer, one verifier |
| KAZ-SIGN OIDs | Antrapolation PEN (configurable) | No public allocation yet; config allows future swap |
| OCSP/CRL signing | PQC-capable in v1 | Revocation must match issuing CA's algorithm |
| Legacy data | Hard cutover | No production data; test-only |

## Architecture

Four new or rewritten modules, each with a narrow interface.

### 1. `PkiCrypto.AlgorithmRegistry`

Single source of truth for every supported algorithm. Maps
`algorithm_id ↔ OID ↔ signer_module ↔ public_key_size ↔ signature_size`.

Registered algorithms at v1:

| ID | Family | OID | Signer module |
|---|---|---|---|
| `rsa2048` | RSA | `1.2.840.113549.1.1.11` (sha256WithRSA) | `PkiCrypto.Signer.Rsa2048` |
| `rsa4096` | RSA | `1.2.840.113549.1.1.11` | `PkiCrypto.Signer.Rsa4096` |
| `ecc_p256` | ECDSA | `1.2.840.10045.4.3.2` (ecdsa-with-SHA256) | `PkiCrypto.Signer.EcdsaP256` |
| `ecc_p384` | ECDSA | `1.2.840.10045.4.3.3` (ecdsa-with-SHA384) | `PkiCrypto.Signer.EcdsaP384` |
| `ml_dsa_44` | ML-DSA (NIST FIPS 204) | `2.16.840.1.101.3.4.3.17` | `PkiCrypto.Signer.MlDsa44` |
| `ml_dsa_65` | ML-DSA | `2.16.840.1.101.3.4.3.18` | `PkiCrypto.Signer.MlDsa65` |
| `ml_dsa_87` | ML-DSA | `2.16.840.1.101.3.4.3.19` | `PkiCrypto.Signer.MlDsa87` |
| `kaz_sign_128` | KAZ-SIGN | `1.3.6.1.4.1.<PEN>.1.1.1` | `PkiCrypto.Signer.KazSign128` |
| `kaz_sign_192` | KAZ-SIGN | `1.3.6.1.4.1.<PEN>.1.1.2` | `PkiCrypto.Signer.KazSign192` |
| `kaz_sign_256` | KAZ-SIGN | `1.3.6.1.4.1.<PEN>.1.1.3` | `PkiCrypto.Signer.KazSign256` |

All OIDs sourced through `Application.get_env(:pki_crypto, :oid_overrides, %{})`
so swapping to NACSA-allocated OIDs is a one-line config change. The actual
Antrapol PEN is a placeholder until confirmed.

Existing classical signer modules under `pki_validation/crypto/signer/` are
lifted into `pki_crypto`. Backwards-compatible aliases remain in
`pki_validation` until Phase 4.

### 2. `PkiCrypto.Csr`

Unified PKCS#10 reader/writer. Replaces scattered `X509.CSR.from_pem`,
`KazSign.generate_csr`, and the `extract_public_key_bytes_from_csr` helpers.

- `parse(pem)` → `{:ok, %{subject_dn, algorithm_id, subject_public_key, raw_tbs, signature}}`.
  Detects algorithm from `subjectPublicKeyInfo.algorithm.oid`, looks it up in
  `AlgorithmRegistry`. Returns `{:error, :unknown_algorithm_oid}` for
  unregistered OIDs.
- `verify_pop(parsed)` — verifies the CSR's self-signature by calling
  `signer.verify(subject_public_key, raw_tbs, signature)`. Required at every
  signing path entry.
- `generate(algorithm_id, private_key, subject_dn)` — builds a PKCS#10 CSR.
  Classical path delegates to `X509.CSR.new`; PQC path builds the TBS
  with `PkiCrypto.Asn1` helpers and signs with the PQC signer module.

### 3. `PkiCrypto.Asn1`

Small hand-rolled DER encoder (~200 LOC). `:public_key` cannot emit a
SubjectPublicKeyInfo with an unknown algorithm OID. `asn1ex` works but is
overkill. Hand-rolled primitives:

```
encode_sequence/1, encode_set/1, encode_oid/1, encode_bit_string/1,
encode_octet_string/1, encode_integer/1, encode_boolean/1, encode_utctime/1,
encode_generalizedtime/1, encode_null/0, encode_tagged/2
```

Unit tests verify byte-exact output against `openssl asn1parse` fixtures on
known inputs. This module does **not** replace `X509` for classical certs —
classical issuance continues through `X509.Certificate.new`. The hand-rolled
path runs only when the issuer or subject is PQC.

### 4. `PkiCrypto.X509Builder`

Cross-algorithm X.509 certificate emitter.

- `build_tbs_cert(csr_parsed, issuer_key_record, subject_dn, validity_days, serial)` →
  `{:ok, tbs_der, signature_algorithm_oid}`. Builds an RFC 5280
  `TBSCertificate`:
  - `subjectPublicKeyInfo` uses the subject's OID + raw public key bytes
    (from `AlgorithmRegistry.encode_public_key/2`).
  - `signatureAlgorithm` uses the issuer's OID.
  - Extensions: `basic_constraints` (CA:TRUE for sub-CA issuance),
    `key_usage` (keyCertSign + cRLSign for CAs, digitalSignature +
    keyEncipherment for leaves), `subject_key_identifier`,
    `authority_key_identifier`.
  - Dispatches to `X509.Certificate.new` only when both issuer and subject
    are classical; otherwise hand-rolled path.
- `sign_tbs(tbs_der, issuer_algorithm_id, issuer_private_key)` → `{:ok, cert_der}`.
  Calls `signer.sign/2`, wraps `(tbs, algId, signature)` into a final
  `Certificate` SEQUENCE.

### 5. `PkiCaEngine.CertificateSigning` (rewrite)

Current module becomes a thin orchestrator:

```elixir
def issue(issuer_key_record, csr_pem, subject_dn, validity_days, serial) do
  with {:ok, csr} <- PkiCrypto.Csr.parse(csr_pem),
       :ok       <- PkiCrypto.Csr.verify_pop(csr),
       {:ok, issuer_priv} <- load_issuer_private_key(issuer_key_record),
       {:ok, tbs_der, _sig_alg} <-
         PkiCrypto.X509Builder.build_tbs_cert(csr, issuer_key_record,
                                              subject_dn, validity_days, serial),
       {:ok, cert_der} <-
         PkiCrypto.X509Builder.sign_tbs(tbs_der, issuer_key_record.algorithm,
                                        issuer_priv) do
    {:ok, cert_der, cert_to_pem(cert_der)}
  end
end
```

Algorithm-family-specific branches (`do_sign_ml_dsa`, `do_sign_kaz`,
`do_sign_with_issuer`) collapse into one path. Existing self-sign logic for
root CAs migrates to the same orchestrator.

### 6. `PkiValidation.Crypto.Signer.*` (extend)

Add `MlDsa44/65/87` + `KazSign128/192/256` signer modules in
`pki_validation/crypto/signer/`, each implementing the existing `Signer`
behaviour (`decode_private_key/1`, `sign/2`, `verify/3`,
`signature_algorithm/0`, etc.). `Registry.@mapping` gains six entries.
`SigningKeyStore` already polymorphically loads and dispatches through the
signer, so it needs no changes. OCSP responder + CRL publisher already sign
via the registered signer of the issuing CA's algorithm, so PQC signing comes
on automatically.

## Data flow — sub-CA issuance under cross-algo root

Example: ECDSA-P384 root signing a KAZ-SIGN-192 sub-CA.

```
Ceremony generates KAZ-SIGN-192 keypair → private shards stored → public key persisted
   │
   ▼
KeyManager clicks "Generate CSR" on sub-CA issuer key
   → PkiCrypto.Csr.generate(:kaz_sign_192, private_key, subject_dn)
   → hand-rolled PKCS#10 with KAZ-SIGN OID + KAZ-SIGN self-signature
   ▼
CA Admin submits CSR to root CA → CertificateSigning.issue(...)
   → PkiCrypto.Csr.parse/1 detects algorithm from OID → :kaz_sign_192
   → PkiCrypto.Csr.verify_pop/1 verifies KAZ-SIGN self-sig with KazSign192 signer
   → PkiCrypto.X509Builder.build_tbs_cert/5:
       - SubjectPublicKeyInfo = (KAZ-SIGN-192 OID, raw PQC public key as BIT STRING)
       - signatureAlgorithm = ECDSA-P384 OID
       - Extensions: basic_constraints CA:TRUE, key_usage=keyCertSign+cRLSign, SKI, AKI
       - Emits DER TBSCertificate
   → PkiCrypto.X509Builder.sign_tbs/3:
       - ECDSA-P384 signs DER(TBS)
       - Wraps (TBS, sigAlg, sig) in final Certificate SEQUENCE
   ▼
Sub-CA activation: paste returned PEM into "Activate" → cert_der persisted
   ▼
Sub-CA issues leaf certs using KAZ-SIGN-192 (same orchestrator, PQC issuer path)
```

## Testing strategy

1. **Unit — ASN.1 builder.** Byte-exact fixture tests against
   `openssl asn1parse` output. Covers TBSCertificate, SubjectPublicKeyInfo,
   Extensions, Name.
2. **Unit — Csr module.** Round-trip
   `generate → parse → verify_pop` for every algorithm in the registry.
   Includes negative tests: tampered signatures, unknown OIDs, malformed
   DER.
3. **Integration — cross-algo matrix.** Parametric test: for every
   (issuer_algo, subject_algo) pair (currently 10×10 = 100, but practically
   trimmed to the 36 non-redundant pairs), generate keys, build CSR, issue
   cert, verify chain. Uses the production orchestrator.
4. **Interop — classical↔classical regressions.** Certs emitted through the
   new path must match the old path byte-for-byte (modulo timestamps) for
   classical issuer + classical subject, so we don't regress today's
   behaviour.
5. **Interop — OpenSSL smoke.** For classical certs, `openssl x509 -text` and
   `openssl verify` continue to work. For PQC certs, `openssl asn1parse`
   walks the structure cleanly (OpenSSL won't verify the signature but the
   structure is valid).

## Phasing

Work splits into four independent PRs. Each leaves the system in a working
state.

### Phase 1 — Algorithm registry + PQC signers
- Lift classical signers from `pki_validation` into `pki_crypto`.
- Add `MlDsa{44,65,87}` and `KazSign{128,192,256}` signer modules
  implementing the existing `Signer` behaviour.
- Build `AlgorithmRegistry`.
- No cert emission changes. `SigningKeyStore` now has access to all
  signers but still only loads classical keys.
- **Ship criterion:** classical codepaths unchanged; new signer modules
  pass unit tests (sign → verify round-trip).

### Phase 2 — `PkiCrypto.Asn1` + `PkiCrypto.X509Builder` (classical issuer, PQC subject)
- Build the hand-rolled ASN.1 helpers.
- Implement `X509Builder` for the classical-issuer-signs-PQC-subject path.
- Implement `PkiCrypto.Csr.parse` + `verify_pop` for PQC subjects.
- Rewire `CertificateSigning` classical path through the new orchestrator
  (classical→classical still delegates to `X509.Certificate.new` inside
  the orchestrator).
- **Ship criterion:** ECDSA root can issue a KAZ-SIGN-192 sub-CA cert.
  Chain validation works. Classical-only regression suite passes.

### Phase 3 — PQC issuer path (combos C + D)
- Implement PQC-issuer branch of `X509Builder.sign_tbs`.
- Implement `PkiCrypto.Csr.generate` for PQC algorithms.
- Migrate KAZ-SIGN CSR generation in `CeremonyOrchestrator` to use the new
  unified `Csr.generate`. Legacy `KazSign.generate_csr` call removed.
- Delete JSON-wrapper cert format from `CertificateSigning`.
- **Ship criterion:** all four combos work end-to-end. comp-5 sub-CA
  (KAZ-SIGN-192) successfully signed by ECDSA-P384 root; hypothetical
  KAZ-SIGN root can sign ECDSA sub-CA.

### Phase 4 — OCSP/CRL PQC signing
- Lift `SigningKeyStore` to `pki_crypto` (or keep in `pki_validation` but
  reference `pki_crypto`'s signer modules).
- Exercise OCSP response signing in ML-DSA and KAZ-SIGN.
- Exercise CRL signing in same.
- **Ship criterion:** revoking a cert on a PQC CA produces a PQC-signed
  OCSP response and a PQC-signed CRL that any relying party with the PQC
  public key can verify.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Antrapol PEN not yet assigned by IANA | Use a configurable placeholder; swap later via config override. Document in release notes. |
| KAZ-SIGN OIDs collide with future NACSA allocation | OIDs are config-driven; swap + reissue is straightforward since we own the trust anchor. |
| PQC signature sizes inflate OCSP responses / CRLs | Document byte-size impact in ops guide. No mitigation in v1 — this is inherent to PQC. |
| Hand-rolled ASN.1 has edge-case bugs | Byte-exact fixture tests against `openssl asn1parse`; `X509` lib continues to handle classical-only certs. |
| Existing KAZ-SIGN CSRs in JSON form become unparseable | No production data; test tenants are disposable. Documented as hard cutover. |
| Ceremony orchestrator's old PQC CSR path (`KazSign.generate_csr`) must be replaced | Covered in Phase 3 migration step. |

## Open questions

- **IANA PEN for Antrapolation** — is one already assigned, or do we need to
  apply? Affects the placeholder OID choice. Does not block implementation;
  tracked as a config swap.
- **OCSP response size limits** — PQC OCSP responses can exceed 4 KB. Does
  any downstream consumer cap responder size? Ops callout only.
- **Composite signatures as v2** — should hybrid certificates be explicitly
  planned for v2, or declared out of roadmap? Tracked separately.

## Definition of done

- Every (issuer_algo, subject_algo) pair in the algorithm registry
  successfully emits a parseable X.509 cert.
- Chain validation passes for every (root_algo, sub_algo, leaf_algo) triple
  exercised in the integration test.
- No JSON-wrapper certificate code paths remain.
- OCSP responses and CRLs are signed in the issuing CA's algorithm,
  including PQC variants.
- Classical-only regression suite unchanged.
- Release notes document the private OID arc for KAZ-SIGN and the
  OpenSSL interop status.
