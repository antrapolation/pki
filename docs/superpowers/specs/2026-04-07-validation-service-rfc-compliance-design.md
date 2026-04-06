# Validation Service RFC Compliance Design

**Date:** 2026-04-07
**Status:** Approved
**Goal:** Make the validation service interoperable with standard PKI clients (browsers, openssl, Java/Go TLS stacks) by implementing RFC 6960 (OCSP), RFC 5280 (CRL), and RFC 5019 (Lightweight OCSP Profile) wire formats and cryptographic signing.

**Approach:** Hybrid — Erlang `:public_key` for CRL (well-supported in OTP 27), custom compiled ASN.1 module for OCSP (OTP lacks built-in OCSP ASN.1 structures). Existing JSON endpoints preserved for portal consumption.

## Constraints & Decisions

- **Interoperability-first** — standard PKI clients must consume OCSP/CRL responses
- **Delegated OCSP signing** — validation service holds its own signing keypair, issued by the CA with `id-kp-OCSPSigning` EKU
- **Algorithm matches issuer** — signing algorithm matches the issuing CA key (ECC, RSA, ML-DSA, etc.)
- **JSON API preserved** — existing JSON endpoints unchanged, new DER endpoints added alongside
- **Start small, design for large** — CRL number tracking and schema choices support future delta CRL without rework

## Section 1: OCSP Responder — RFC 6960 Compliance

### New DER Endpoints

| Method | Path | Content-Type (Request) | Content-Type (Response) | Purpose |
|--------|------|------------------------|------------------------|---------|
| POST | `/ocsp/der` | application/ocsp-request | application/ocsp-response | RFC 6960 standard |
| GET | `/ocsp/der/{base64-request}` | — | application/ocsp-response | RFC 5019 lightweight |

Existing `POST /ocsp` (JSON) unchanged.

### ASN.1 Module

Compile the OCSP ASN.1 spec from RFC 6960 Appendix B into an Erlang module (`OCSP.asn1`). This provides native `OCSPRequest`, `OCSPResponse`, `BasicOCSPResponse`, `SingleResponse`, `CertID` record types. The compiled module lives in `src/pki_validation/asn1/`.

### Request Parsing

A `CertID` in an OCSP request contains `{hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber}`. The responder:

1. Decodes DER request, extracts `CertID` list
2. Matches against known issuer keys (by comparing `issuerKeyHash` against stored issuer public key hashes)
3. Looks up serial number in `certificate_status` table (same as today)

### Response Signing

Each tenant's validation service holds a delegated OCSP signing keypair per issuer key. The signing flow:

1. Build `BasicOCSPResponse` with `SingleResponse` entries (status, thisUpdate, nextUpdate, certID)
2. Set `producedAt` to current UTC
3. Sign the `responseData` TBS bytes using the delegated key (algorithm matches the issuer)
4. Attach the OCSP signing certificate in the `certs` field
5. Wrap in `OCSPResponse` with `responseStatus: successful`

### Nonce Support

Optional per RFC 6960 section 4.4.1. If the request includes a nonce extension, echo it back in the response. If not, omit it.

### Error Responses

Return proper `OCSPResponseStatus` codes in DER:

- `malformedRequest` (1) — unparseable DER
- `internalError` (2) — DB/signing failure
- `unauthorized` (6) — request targets an issuer this responder doesn't serve

### Caching

Existing ETS cache continues — caches `SingleResponse` data (not signed bytes). DER responses are signed fresh but DB lookup is cached. HTTP headers: `Cache-Control: public, max-age=300, no-transform` and `ETag` based on serial + status hash.

## Section 2: CRL Publisher — RFC 5280 Compliance

### New DER Endpoints

| Method | Path | Content-Type | Purpose |
|--------|------|-------------|---------|
| GET | `/crl/der` | application/pkix-crl | Default issuer CRL |
| GET | `/crl/der/{issuer_key_id}` | application/pkix-crl | CRL for specific issuer |

Existing `GET /crl` (JSON) unchanged.

### CRL Generation via `:public_key`

Dual-output generator. The DER path uses Erlang's `:public_key` module:

1. Build the TBSCertList record:
   - `version`: v2
   - `signature`: algorithm OID matching the issuer key
   - `issuer`: issuer DN (from the signing certificate)
   - `thisUpdate`: current UTC
   - `nextUpdate`: thisUpdate + validity period (default 1 hour, configurable)
   - `revokedCertificates`: list of `{serialNumber, revocationDate, extensions: [{cRLReason, reason}]}`
2. Sign the DER-encoded TBS bytes with the CRL signing key
3. Assemble the full `CertificateList` record and DER-encode

### CRL Signing Key

Uses the same delegated signing keypair as the OCSP responder. The CA-issued certificate includes both `id-kp-OCSPSigning` EKU and `id-ce-cRLSign` key usage bit. All CRL signing goes through the delegated key — the validation service never holds issuer keys directly.

### CRL Number Extension (RFC 5280 section 5.2.3)

Monotonically increasing `crl_number` tracked in `crl_metadata` table. Incremented on every generation. Required for future delta CRL support and helps clients detect stale CRLs.

### Authority Key Identifier Extension (RFC 5280 section 5.2.1)

Included in every CRL, matching the signing key. Required for clients to chain the CRL back to the issuer.

### Pre-signed CRL Caching

GenServer continues periodic regeneration (default 1 hour). Stores signed DER bytes in memory — no re-signing on every request. JSON endpoint continues to generate from DB on each call. HTTP headers: `Cache-Control: public, max-age=3600, no-transform`, `Last-Modified`, `ETag`, `Expires`.

### Delta CRL (deferred)

CRL number tracking and `revokedCertificates` ordering by `revoked_at` means delta CRL support can be added later by querying "revocations since CRL number X". Not implemented now, but schema supports it without changes.

## Section 3: Delegated Signing Key Management

### Signing Key Lifecycle

1. **Provisioning** — When a CA issuer key is activated (ceremony complete), the CA engine issues a delegated OCSP/CRL signing certificate to the validation service. This certificate includes:
   - `id-kp-OCSPSigning` EKU (RFC 6960 section 4.2.2.2)
   - `id-ce-cRLSign` key usage bit
   - Short validity (30 days) — standard practice for OCSP signing certs
   - `id-pkix-ocsp-nocheck` extension (RFC 6960 section 4.2.2.2.1) — tells clients not to check the OCSP signing cert's own revocation status (avoids infinite loop)

2. **Storage** — Private key encrypted at rest using AES-256-GCM + PBKDF2 (same pattern as `pki_crypto`). Decrypted into memory on service start using an activation password (from env var or Key Vault grant). HSM storage via PKCS#11/SoftHSM2 supported for production.

3. **Rotation** — Before the signing cert expires, the CA engine issues a new one. The validation service loads both during a grace period (serves responses signed with the new cert, old cert still valid for cached responses in transit). A `/notify/signing-key-rotation` internal endpoint handles this.

4. **Per-Issuer Mapping** — A tenant with multiple issuer keys (e.g., one RSA, one ML-DSA) gets one delegated signing keypair per issuer. The responder selects the correct signing key by matching the `issuerKeyHash` from the OCSP request or the issuer context for CRL generation.

### New Schema: `signing_key_config`

| Field | Type | Purpose |
|-------|------|---------|
| id | binary_id (UUIDv7) | Primary key |
| issuer_key_id | binary_id | FK to CA issuer key |
| algorithm | string | Matches issuer (ecc_p256, rsa4096, ml_dsa, etc.) |
| certificate_pem | text | The delegated signing certificate |
| encrypted_private_key | binary | AES-256-GCM encrypted private key |
| not_before | utc_datetime_usec | Signing cert validity start |
| not_after | utc_datetime_usec | Signing cert validity end |
| status | string | active / pending_rotation / expired |
| inserted_at / updated_at | utc_datetime_usec | Timestamps |

### Activation Flow

On service startup:

1. Load all `signing_key_config` records with status `active`
2. Decrypt private keys into memory (GenServer state or ETS)
3. Build issuer-key to signing-key lookup map
4. Log which issuers are ready for signing

If no signing key exists for an issuer, DER endpoints return `unauthorized` / 503 for that issuer. JSON endpoints continue working (they don't sign).

## Section 4: CRL Metadata & Schema Changes

### New Table: `crl_metadata`

| Field | Type | Purpose |
|-------|------|---------|
| id | binary_id (UUIDv7) | Primary key |
| issuer_key_id | binary_id | FK to issuer key (unique) |
| crl_number | integer | Monotonically increasing, starts at 1 |
| last_generated_at | utc_datetime_usec | When last CRL was built |
| last_der_bytes | binary | Cached signed DER CRL |
| last_der_size | integer | Size in bytes (monitoring/alerting) |
| generation_count | integer | Total CRLs generated (metrics) |
| inserted_at / updated_at | utc_datetime_usec | Timestamps |

### Changes to Existing `certificate_status` Table

Add one column:

| Field | Type | Purpose |
|-------|------|---------|
| issuer_name_hash | binary | SHA-1 hash of issuer DN (for CertID matching in OCSP) |

Computed once at certificate issuance time. The `issuerKeyHash` is derived from the issuer's public key via `signing_key_config.certificate_pem` at startup and held in memory.

### Index Changes

- Add composite index on `(issuer_key_id, serial_number)` for faster OCSP lookups scoped to an issuer
- Add index on `(status, revoked_at)` for efficient CRL generation queries

### CRL Number Flow

1. `SELECT crl_number FROM crl_metadata WHERE issuer_key_id = ? FOR UPDATE`
2. Generate CRL with that number
3. Sign and store DER bytes
4. Increment `crl_number` and update `last_generated_at`
5. All in one transaction — prevents duplicate CRL numbers

## Section 5: Router, HTTP Headers & Content Negotiation

### Full Route Table

```
# Existing (unchanged)
GET   /health                        JSON health check
POST  /ocsp                          JSON OCSP lookup (portals)
GET   /crl                           JSON CRL (portals)
POST  /notify/issuance               Internal API (bearer auth)
POST  /notify/revocation             Internal API (bearer auth)

# New DER endpoints
POST  /ocsp/der                      RFC 6960 DER OCSP response
GET   /ocsp/der/{base64-request}     RFC 5019 GET OCSP
GET   /crl/der                       RFC 5280 DER CRL
GET   /crl/der/{issuer_key_id}       DER CRL for specific issuer

# New internal endpoints
POST  /notify/signing-key-rotation   Signing key update (bearer auth)
```

### HTTP Cache Headers

OCSP DER responses:
```
Cache-Control: public, max-age=300, no-transform
ETag: "<sha256 of response bytes>"
Date: <RFC 7231 timestamp>
```

CRL DER responses:
```
Cache-Control: public, max-age=3600, no-transform
Last-Modified: <thisUpdate from CRL>
ETag: "<crl_number>-<issuer_key_id_short>"
Expires: <nextUpdate from CRL>
```

### Request Size Limits

- OCSP POST body: max 10KB
- CRL response: no limit, but `last_der_size` in `crl_metadata` enables monitoring

### Error Handling

DER endpoints return proper OCSP/CRL error responses, not JSON. For OCSP, the `OCSPResponseStatus` enum is used. For CRL, 503 with empty body if generation fails. JSON endpoints continue returning JSON errors.

## Section 6: Testing Strategy

### Unit Tests

- **ASN.1 encoding/decoding** — Round-trip tests for OCSP request parsing, OCSP response building, CRL DER generation. Verify against known-good DER bytes.
- **CertID matching** — Test issuerNameHash and issuerKeyHash computation, correct issuer selection with multiple issuers.
- **Signing key config schema** — Changeset validations, status transitions, per-issuer uniqueness.
- **CRL metadata** — CRL number incrementing, concurrent generation safety, DER byte caching.
- **Response signing** — Sign and verify round-trip for each algorithm (ECC-P256, ECC-P384, RSA-4096, ML-DSA). Verify with `:public_key.verify/4`.
- **Nonce handling** — Request with nonce echoed back, request without nonce omitted.
- **Error responses** — Malformed DER returns `malformedRequest`, unknown issuer returns `unauthorized`, missing signing key returns `internalError`.

### Integration Tests

- **Full OCSP DER flow** — Issue cert via `/notify/issuance`, query `/ocsp/der` with DER-encoded request, verify signed DER response, decode and check status.
- **Full CRL DER flow** — Revoke cert, fetch `/crl/der`, decode DER, verify signature, check serial in revoked list.
- **GET OCSP** — Base64-encode DER request, fetch via `/ocsp/der/{b64}`, verify same response as POST.
- **Signing key rotation** — Notify rotation, verify new responses signed with new key, old key valid during grace period.
- **Multi-issuer** — Two issuers with different algorithms, verify correct signing key selected.
- **Cache headers** — Verify `Cache-Control`, `ETag`, `Expires` present and correct.

### OpenSSL Interop Tests

Using `System.cmd/3` to invoke `openssl`:

- `openssl ocsp -reqout` to generate a real OCSP request DER, POST to `/ocsp/der`, pipe response through `openssl ocsp -respin -verify`
- `openssl crl -inform DER` to parse and verify the CRL output
- `openssl verify -crl_check` with the CRL to verify a certificate's revocation status

### Existing Tests

All current JSON endpoint tests remain unchanged. Existing 54 ExUnit tests continue passing.
