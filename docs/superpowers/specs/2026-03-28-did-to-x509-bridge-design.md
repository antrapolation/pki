# DID-to-X.509 Certificate Bridge — Design Spec

## Overview

Bridge between the SSDID (Self-Sovereign Identity) ecosystem and the STRAPTrust PKI system. Allows SSDID wallet users to request X.509 certificates for their DIDs directly from the PKI Certificate Authority.

**Scope:** PKI-side changes only (beta.3). SSDID-side changes (ssdid_ca extension, wallet UI) are a separate spec/plan cycle.

## Problem

SSDID users hold DIDs and Verifiable Credentials but lack X.509 certificates needed for:
- DSA (Digital Signature Act) compliance in Malaysia
- TLS client authentication
- Document signing accepted by legacy systems
- Government and enterprise systems that require X.509

The PKI CA can issue certificates but doesn't understand DIDs. This bridge closes the gap.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Initiator | Wallet user (self-service) | Users control their own identity |
| Certificate Subject | `CN=did:ssdid:<id>` | DID as Subject CN — simple, machine-readable |
| DID Verification | Wallet provides DID Document + proof | CA verifies locally, no registry dependency |
| Algorithm | 1:1 match (wallet algo = cert algo) | Both systems share same crypto components (ExCcrypto, BouncyCastle, KAZ-Sign) |
| Delivery | Async with callback | PQC signing may take time; allows manual approval in future |
| Integration location | Both sides — new PKI API endpoint + SSDID client extension |

## Supported Algorithms (1:1 Mapping)

Both SSDID and PKI share the same crypto stack. No fallback or conversion needed.

| SSDID Verification Method | PKI Certificate Algorithm |
|--------------------------|--------------------------|
| `Ed25519VerificationKey2020` | Ed25519 |
| `EcdsaSecp256r1VerificationKey2019` | ECC-P256 |
| `EcdsaSecp384VerificationKey2019` | ECC-P384 |
| `KazSign128VerificationKey2024` | KAZ-SIGN-128 |
| `KazSign192VerificationKey2024` | KAZ-SIGN-192 |
| `KazSign256VerificationKey2024` | KAZ-SIGN-256 |
| `MlDsa44VerificationKey2024` | ML-DSA-44 |
| `MlDsa65VerificationKey2024` | ML-DSA-65 |
| `MlDsa87VerificationKey2024` | ML-DSA-87 |
| `SlhDsa*VerificationKey2024` | SLH-DSA (matching variant) |

## Flow

```
Wallet                    PKI CA Engine
  |                            |
  |  1. POST /api/v1/did-certificate
  |    {did, did_document, proof,
  |     algorithm, callback_url,
  |     cert_profile_id}       |
  |--------------------------->|
  |                            |
  |  2. Return request_id      |
  |     + status: "pending"    |
  |<---------------------------|
  |                            |
  |                            | 3. Verify proof against DID Document
  |                            | 4. Extract public key (multibase decode)
  |                            | 5. Map verification method to PKI algorithm
  |                            | 6. Generate CSR internally (CN=did:ssdid:...)
  |                            | 7. Sign certificate with issuer key
  |                            | 8. Store cert + update request status
  |                            |
  |  9. POST {callback_url}    |
  |     {request_id, status,   |
  |      did}                  |
  |<---------------------------|
  |                            |
  | 10. GET /api/v1/did-certificate/{request_id}
  |--------------------------->|
  |                            |
  | 11. Return cert_pem,       |
  |     serial, validity       |
  |<---------------------------|
```

## API Endpoints (PKI Side)

### POST /api/v1/did-certificate

Request a certificate for a DID. Requires `INTERNAL_API_SECRET` or API key auth.

**Request:**
```json
{
  "did": "did:ssdid:abc123",
  "did_document": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:ssdid:abc123",
    "verificationMethod": [{
      "id": "did:ssdid:abc123#key-1",
      "type": "EcdsaSecp256r1VerificationKey2019",
      "controller": "did:ssdid:abc123",
      "publicKeyMultibase": "uABC..."
    }],
    "authentication": ["did:ssdid:abc123#key-1"],
    "assertionMethod": ["did:ssdid:abc123#key-1"]
  },
  "proof": {
    "type": "EcdsaSecp256r1Signature2019",
    "created": "2026-03-28T10:00:00Z",
    "verificationMethod": "did:ssdid:abc123#key-1",
    "proofPurpose": "authentication",
    "proofValue": "z2rRcczYoFvJC..."
  },
  "callback_url": "https://app.example.com/ssdid/cert-callback",
  "cert_profile_id": "<uuid>"
}
```

**Response (202 Accepted):**
```json
{
  "request_id": "<uuid>",
  "status": "pending",
  "did": "did:ssdid:abc123"
}
```

**Error responses:**
- `400` — missing required fields
- `401` — unauthorized (bad API key)
- `422` — proof verification failed, unsupported algorithm, invalid DID format

### GET /api/v1/did-certificate/{request_id}

Retrieve certificate request status and issued certificate.

**Response (pending):**
```json
{
  "request_id": "<uuid>",
  "status": "pending",
  "did": "did:ssdid:abc123"
}
```

**Response (issued):**
```json
{
  "request_id": "<uuid>",
  "status": "issued",
  "did": "did:ssdid:abc123",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "serial_number": "abc123def456",
  "not_before": "2026-03-28T10:00:00Z",
  "not_after": "2027-03-28T10:00:00Z"
}
```

**Response (rejected):**
```json
{
  "request_id": "<uuid>",
  "status": "rejected",
  "did": "did:ssdid:abc123",
  "reason": "proof verification failed"
}
```

## Data Model

### did_certificate_requests (new table)

```elixir
schema "did_certificate_requests" do
  field :did, :string                  # did:ssdid:abc123
  field :did_document, :map            # full W3C DID Document JSON
  field :proof, :map                   # W3C Data Integrity proof
  field :algorithm, :string            # resolved PKI algorithm name
  field :public_key, :binary           # extracted from DID Document (raw bytes)
  field :status, :string               # pending | processing | issued | rejected
  field :callback_url, :string         # where to POST when done
  field :cert_profile_id, :binary_id   # FK to cert profile
  field :issued_cert_serial, :string   # serial of issued cert (when issued)
  field :rejection_reason, :string     # reason for rejection (when rejected)
  field :ca_instance_id, :binary_id    # tenant context

  timestamps()
end
```

Primary key: UUIDv7 (consistent with all other PKI schemas).

Statuses: `pending` -> `processing` -> `issued` | `rejected`

## Proof Verification Logic

The CA Engine verifies the DID proof without calling the SSDID Registry:

1. **Parse DID Document** — extract the verification method matching `proof.verificationMethod` key ID
2. **Validate DID format** — must match `did:ssdid:<base64url>` pattern
3. **Validate DID consistency** — `did_document.id` must equal the `did` field
4. **Decode public key** — multibase decode `publicKeyMultibase` to raw bytes
5. **Resolve algorithm** — map `verificationMethod.type` to PKI algorithm name
6. **Reconstruct signed payload** — per W3C Data Integrity: `hash(document_without_proof) || hash(proof_options_without_proofValue)`
7. **Verify signature** — using extracted public key and resolved algorithm
8. **Check proof freshness** — `proof.created` must be within 5 minutes of current time
9. **Check proof purpose** — must be `authentication` or `assertionMethod`

If any step fails, request is rejected with a descriptive reason.

## Certificate Generation

After proof verification:

1. **Build CSR internally** — Subject: `CN=did:ssdid:<id>`, public key from DID Document
2. **Select issuer key** — use the active issuer key for the tenant matching the requested algorithm
3. **Apply cert profile** — validity period, key usage, extensions from the cert profile
4. **Sign certificate** — using `CertificateSigning.sign_certificate/4` (existing PKI module)
5. **Store certificate** — in `issued_certificates` table with serial number
6. **Update request** — set status to `issued`, store `issued_cert_serial`
7. **Send callback** — POST to `callback_url` with request_id and status

## Callback Notification

When certificate status changes to `issued` or `rejected`:

```
POST {callback_url}
Content-Type: application/json

{
  "request_id": "<uuid>",
  "status": "issued",
  "did": "did:ssdid:abc123"
}
```

Callback is fire-and-forget — if it fails, the wallet can poll via GET endpoint. No retry logic in beta.3.

## New Modules (PKI Side)

### PkiCaEngine.DidCertificateBridge

Main orchestrator module:

- `request_certificate/2` — validate input, verify proof, create request record, trigger async signing
- `get_request/1` — fetch request by ID
- `list_requests/2` — list requests by ca_instance_id with filters

### PkiCaEngine.DidCertificateBridge.ProofVerifier

DID proof verification:

- `verify/2` — takes DID Document + proof, returns `:ok` or `{:error, reason}`
- `extract_public_key/1` — extracts and decodes public key from DID Document
- `map_algorithm/1` — maps W3C verification method type to PKI algorithm name

### PkiCaEngine.DidCertificateBridge.DidCertificateRequest

Ecto schema for `did_certificate_requests` table.

### PkiCaEngine.Api.DidCertificateController

API controller with two actions:

- `create/1` — POST /api/v1/did-certificate
- `show/2` — GET /api/v1/did-certificate/{request_id}

## Security Considerations

- **No registry trust required** — CA verifies proof cryptographically against the provided DID Document. A tampered DID Document would have an invalid proof signature.
- **Proof freshness** — 5-minute window prevents replay attacks
- **API authentication** — endpoints require `INTERNAL_API_SECRET` bearer token (same as other PKI API endpoints)
- **DID format validation** — rejects non-SSDID DIDs
- **Algorithm allowlist** — only supported algorithms are accepted; unknown types rejected
- **Rate limiting** — inherits from existing PKI API rate limiting
- **Audit trail** — certificate issuance logged in audit events (existing PKI audit system)

## What's NOT in Scope (beta.3)

- SSDID-side changes (ssdid_ca extension, wallet "Request Certificate" screen) — separate spec
- Certificate revocation via DID deactivation — future integration
- Registry-based DID Document verification (CA calls registry) — future enhancement
- Manual approval workflow — auto-approved in beta.3, approval flow in future
- Callback retry logic — fire-and-forget in beta.3

## Testing

- Unit tests for ProofVerifier (valid proof, expired proof, wrong algorithm, tampered document)
- Unit tests for algorithm mapping (all 10+ verification method types)
- Integration test for full flow (request -> verify -> issue -> retrieve)
- API tests for both endpoints (happy path, auth failure, invalid proof, unknown request_id)
- Playwright e2e test calling the DID certificate endpoint with a test DID + proof
