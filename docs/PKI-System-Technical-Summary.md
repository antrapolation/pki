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
                          +---------------------------+
                          |    Platform Portal (:4006)|
                          |  Tenant & User Management |
                          +------------+--------------+
                                       |
                 +---------------------+---------------------+
                 |                                           |
     +-----------+-----------+               +---------------+-----------+
     |   CA Portal (:4004)  |               |   RA Portal (:4005)       |
     |   Key & Cert Mgmt UI |               |   CSR & Profile Mgmt UI  |
     +-----------+-----------+               +---------------+-----------+
                 |                                           |
     +-----------+-----------+               +---------------+-----------+
     |      CA Engine       |               |       RA Engine           |
     |  Signing & Ceremony  |<--- REST ---->|  CSR Processing & DCV    |
     |  (key-isolated node) |               |  REST API for Integrations|
     +-----------+-----------+               +---------------+-----------+
                 |                                           |
                 +---------------------+---------------------+
                                       |
                          +------------+--------------+
                          |   Validation Service      |
                          |   OCSP / CRL / LDAP       |
                          +---------------------------+
                                       |
                              +--------+--------+
                              |   PostgreSQL    |
                              |  (per-tenant DB)|
                              +-----------------+
```

Each box runs as an independent Erlang/OTP node (systemd service). The CA Engine is the only node with access to signing keys -- portals communicate via authenticated internal APIs.

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

- **Database-level isolation**: Each tenant gets a dedicated PostgreSQL database (`pki_tenant_<uuid>`) with separate `ca` and `ra` schemas.
- **Runtime isolation**: A `DynamicSupervisor` spawns per-tenant processes, each with dedicated Ecto Repos routed to the correct database.
- **Identity isolation**: Platform-level `user_profiles` table with role-based tenant access (`user_tenant_roles`). Per-tenant CA/RA user stores for portal-specific roles.
- **Lazy start**: Tenant engines start on first request and register in an ETS-backed global registry.

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

Six independent systemd services, each an Erlang node with distribution enabled:

| Service | Port | Role |
|---------|------|------|
| `pki-platform-portal` | 4006 | Tenant management, cross-tenant admin |
| `pki-ca-portal` | 4004 | CA admin UI (bundles CA Engine) |
| `pki-ra-portal` | 4005 | RA admin UI (bundles RA Engine) |
| `pki-ca-engine` | 4001 | Standalone CA signing (optional HA node) |
| `pki-ra-engine` | 4002 | Standalone RA processing (optional HA node) |
| `pki-validation` | 4003 | OCSP, CRL, LDAP (read-only, horizontally scalable) |

**Scaling**: Additional engine nodes join the cluster via Erlang distribution. Validation nodes are stateless and horizontally scalable behind a load balancer. Mnesia replicates activation state across CA Engine nodes for HA.

**Reverse Proxy**: Caddy with automatic Let's Encrypt TLS (`*.straptrust.com`).
**Connection Pooling**: PgBouncer in transaction mode for PostgreSQL connection efficiency.
