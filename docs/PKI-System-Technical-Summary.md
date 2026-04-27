# PQC PKI System -- Technical Summary

**Antrapolation Technology Sdn Bhd**
April 2026

---

## Overview

A multi-tenant, post-quantum-ready Certificate Authority (CA) and Registration Authority (RA) platform built on Elixir/Erlang OTP. The system manages the full certificate lifecycle -- from key ceremony and CSR submission to issuance, revocation, and validation -- while supporting both classical (RSA, ECC) and post-quantum cryptographic algorithms (ML-DSA, SLH-DSA, KAZ-SIGN).

Designed for SaaS multi-tenant deployment and single-tenant on-premises configurations from the same codebase.

---

## System Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────┐
│  Caddy (80/443)                     │
│  admin.* → pki_platform :4006       │
│  <tenant>.* → pki_tenant (per-node) │
└────────┬────────────────────────────┘
         │
┌────────▼─────────────────────────────────────┐
│  pki_platform BEAM (1 node)                   │
│  Platform portal :4006                        │
│  Tenant lifecycle management                  │
│  PostgreSQL: tenant registry, platform users, │
│              platform audit trail             │
└────────┬─────────────────────────────────────┘
         │  :peer spawn / distributed Erlang
┌────────▼─────────────────────────────────────┐
│  pki_tenant BEAM (one node per tenant)        │
│  CA portal + CA engine (in-process)           │
│  RA portal + RA engine (in-process)           │
│  Validation: OCSP/CRL (in-process)            │
│  State: local Mnesia (disc_copies)            │
└──────────────────────────────────────────────┘
```

The platform BEAM manages tenant lifecycle (provision, deprovision, spawn). Each tenant gets its own BEAM node with full CA/RA/Validation capability. Portals and engines are co-located in the tenant BEAM — no inter-process HTTP between them. OCSP and CRL requests are served from the same tenant BEAM; CDP/OCSP URLs in issued certificates point at the tenant's subdomain.

PostgreSQL is used only for platform-tier state (tenant registry, platform user accounts, platform audit trail). All CA, RA, and validation state lives in local Mnesia on the tenant BEAM node — each tenant is isolated by process boundary, not database schema.

---

## Cryptographic Algorithm Support

| Category | Algorithms | Standard |
|----------|-----------|----------|
| **Post-Quantum Signing** | ML-DSA-44, ML-DSA-65, ML-DSA-87 | NIST FIPS 204 |
| **Post-Quantum Signing** | SLH-DSA-SHA2-128f/s, 192f/s, 256f/s | NIST FIPS 205 |
| **National PQC** | KAZ-SIGN-128, KAZ-SIGN-192, KAZ-SIGN-256 | Malaysia PQC Standard |
| **Classical Signing** | RSA-4096, ECC-P256, ECC-P384 | PKCS / NIST |

Algorithm dispatch is protocol-based and extensible -- new algorithms are added as modules implementing `generate_keypair/1`, `sign/3`, `verify/4`.

PQC operations are performed via native NIFs (liboqs bindings for ML-DSA/SLH-DSA) and a Java/JRuby bridge for KAZ-SIGN.

---

## Multi-Tenant Isolation

- **Process-boundary isolation**: Each tenant runs a dedicated `pki_tenant` BEAM node, spawned via `:peer` by `pki_platform`. CA, RA, and Validation services are in-process on that node — not shared with other tenants.
- **State isolation**: All CA/RA/Validation state (keys, certificates, certificate status, CRL data) lives in local Mnesia (`disc_copies`) on the tenant's BEAM node. No cross-tenant Mnesia replication.
- **Identity isolation**: Platform-level `user_profiles` table with role-based tenant access (`user_tenant_roles`). Per-tenant CA/RA user stores for portal-specific roles (CA Admin, Key Manager, RA Admin, RA Officer, Auditor).
- **On-demand start**: Tenant BEAM nodes start on provisioning and are supervised by `pki_platform`. State survives node restarts via Mnesia persistence.

---

## Key Ceremony & Threshold Activation

Root and sub-CA key generation follows a formal ceremony protocol using **Shamir Secret Sharing (K-of-N)**:

1. CA Admin initiates ceremony, specifying algorithm, keystore, threshold (e.g., 3-of-5), and subject DN.
2. Key Managers and an Auditor authenticate and join.
3. Keypair is generated (software keystore or HSM via PKCS#11).
4. Private key is split into N shares; each share is encrypted with the custodian's password (Argon2 + AES-256-GCM).
5. Encrypted shares are persisted; plaintext private key is wiped from memory.
6. **Activation** requires K custodians to re-authenticate and provide their shares. The recovered key is held in-memory with a configurable timeout (default 1 hour), then auto-cleared.

Both synchronous (all present) and asynchronous (join within time window) ceremony modes are supported.

---

## Certificate Lifecycle

| Stage | Component | Description |
|-------|-----------|-------------|
| **CSR Submission** | RA Engine API | REST API or portal upload. Subject DN validated against cert profile policy. |
| **Domain Validation** | RA Engine | HTTP-01 and DNS-01 challenge types. Automated polling with expiry. |
| **Review & Approval** | RA Portal / API | RA Officer reviews, approves, or rejects with reason. |
| **Issuance** | CA Engine | Signs CSR with activated issuer key. Stores certificate (DER + PEM). |
| **Revocation** | RA Engine API | Per-certificate revocation with RFC 5280 reason codes. |
| **Status Checking** | Validation Service | OCSP responder and CRL publisher with Mnesia hot cache. |

---

## Security Design

- **Authentication**: Argon2-hashed passwords, session-based portal auth with idle timeout, IP pinning, and user-agent fingerprinting. API keys (SHA3-256 hashed) with per-key scopes and rate limits.
- **Authorization**: Role-based access control. CA roles: CA Admin, Key Manager, RA Admin, Auditor. RA roles: RA Admin, RA Officer, Auditor. Platform roles: Super Admin, Tenant Admin.
- **Rate Limiting**: Per-IP and per-API-key token bucket (Hammer + Mnesia). Configurable per endpoint.
- **Audit Trail**: Hash-chained, append-only event log (SHA3-256). Each event links to the previous via cryptographic hash. Chain integrity is independently verifiable.
- **Key Isolation**: Private keys never leave the CA Engine node. HSM support via PKCS#11 (SoftHSM provider included).

---

## REST API (RA Engine)

The RA Engine exposes a scoped REST API at `/api/v1` for external integrations:

- **CSR**: Submit, list, approve, reject
- **Certificates**: List, retrieve by serial, revoke
- **Domain Validation**: Create HTTP-01/DNS-01 challenges, verify, check status
- **Certificate Profiles**: CRUD for issuance policies (subject DN, key usage, validity, CRL/OCSP)
- **API Keys**: Create, rotate, revoke with per-key scopes and IP whitelist
- **Webhooks**: Event notifications with configurable delivery and retry

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Language & Runtime | Elixir 1.18 / Erlang OTP 26 |
| Web Framework | Phoenix 1.8 + LiveView 1.1 |
| HTTP Server | Bandit 1.5 |
| Database | PostgreSQL (per-tenant isolation) |
| Distributed Cache | Mnesia (OCSP cache, service registry, rate limits) |
| PQC Crypto | liboqs NIF (ML-DSA, SLH-DSA), JRuby bridge (KAZ-SIGN) |
| Classical Crypto | ex_ccrypto (RSA, ECC, AES, SHA) |
| X.509 Operations | Custom x509 library (cert/CSR/CRL encoding) |
| Secret Sharing | KeyX (Shamir SSS, Vault-compatible) |
| HSM Interface | Rust NIF (PKCS#11 / SoftHSM) |
| Frontend | Tailwind CSS, esbuild, Heroicons |

---

## Deployment

Two systemd service types (no containers required):

| Service | Count | Port | Role |
|---------|-------|------|------|
| `pki-platform` | 1 | 4006 | Platform portal + tenant lifecycle management |
| `pki-tenant-<slug>` | 1 per tenant | dynamic | CA portal, RA portal, OCSP/CRL — per-tenant BEAM |

**Scaling**: Additional `pki_tenant` nodes are spawned as tenants are provisioned. Each tenant node is fully self-contained — no shared state with other tenant nodes.

**Reverse Proxy**: Caddy with automatic Let's Encrypt TLS. Routes `admin.*` to `pki-platform :4006`; routes `<tenant>.*` to the corresponding tenant BEAM node.

**Database**: PostgreSQL is used only by `pki_platform` (tenant registry, platform users, platform audit trail). Tenant nodes use only Mnesia.
