# STRAPTrust — Post-Quantum Certificate Authority

A Post-Quantum Cryptography ready Certificate Authority infrastructure for issuing and managing digital certificates. Built for Malaysia's national PQC initiative.

**Product of [Antrapolation Technology Sdn Bhd](https://antrapol.com)**

**Latest release:** [v1.0.0-beta.2](https://vcs.antrapol.tech:3800/Incubator/pki/releases/tag/v1.0.0-beta.2)

## Supported Algorithms

| Algorithm | Type | Status |
|-----------|------|--------|
| **KAZ-SIGN** | Malaysia local PQC | Planned |
| **ML-DSA** (FIPS 204) | NIST PQC standard | Supported |
| **RSA-4096** | Classical signing | Supported |
| **ECC-P256/P384** | Classical signing | Supported |
| **ECDH-P256** | Key Encapsulation (KEM) | Supported |

## Architecture

```
                         Internet
                            |
                        +-------+
                        | Caddy |  HTTPS + Auto Let's Encrypt
                        +---+---+
         +------------------+------------------+-----------+
         |                  |                  |           |
   +-----v------+    +-----v------+    +-----v------+  +-v----------+
   |  Platform   |    | CA Portal  |    | RA Portal  |  | Validation |
   |   Portal    |    |   :4002    |    |   :4004    |  |   :4005    |
   |   :4006     |    +-----+------+    +-----+------+  +------------+
   +-----+-------+          |                 |               ^
         |            +-----v------+    +-----v------+        |
         |            | CA Engine  |    | RA Engine  |--------+
         |            |   :4001    |<---|   :4003    |  notify
         |            |            |    +------------+
         |            | Modules:   |
         |            | Credential Manager
         |            | Key Ceremony Manager
         |            | Key Vault + Keypair ACL
         |            | Certificate Signing
         |            +-----+------+
         |                  |
   +-----v------------------v-----------------------------------+
   |                   PostgreSQL 17                             |
   |                                                             |
   |  pki_platform    pki_tenant_{uuid}    pki_tenant_{uuid}     |
   |  (shared)        +-- ca.*             +-- ca.*              |
   |                  +-- ra.*             +-- ra.*              |
   |                  +-- validation.*     +-- validation.*      |
   |                  +-- audit.*          +-- audit.*           |
   +-------------------------------------------------------------+
```

| Service | Port | Purpose |
|---------|------|---------|
| CA Engine | 4001 | Core CA — key ceremonies, certificate signing, credentials |
| CA Portal | 4002 | CA Admin GUI (Phoenix LiveView) |
| RA Engine | 4003 | Registration Authority — CSR processing, REST API |
| RA Portal | 4004 | RA Admin GUI (Phoenix LiveView) |
| Validation | 4005 | OCSP responder + CRL publisher |
| Platform Portal | 4006 | Tenant management GUI |
| PostgreSQL | 5432 | Multi-tenant database (one DB per tenant) |
| SoftHSM2 | — | PKCS#11 HSM simulator |

## What's New in beta.2

### Multi-Tenant Architecture
- One tenant = one isolated PostgreSQL database with 4 schemas (ca/ra/validation/audit)
- Platform Portal for tenant CRUD — create, suspend, activate, delete tenants
- Dynamic per-tenant database routing via `TenantRepo`

### Cryptographic Credentials
- Every user gets dual keypairs — **signing** (ECC-P256) + **KEM** (ECDH-P256)
- Private keys encrypted with password-derived key (PBKDF2, 310K iterations)
- Public keys attested by creating admin and verified at every login

### Key Vault & Keypair ACL
- **3 protection modes:** `credential_own` (ACL KEM encryption), `split_auth_token` (Shamir password split), `split_key` (Shamir key split)
- Keypair ACL with signed grant envelopes — cryptographic access control for keypairs
- Grant signatures verified on every read

### Key Ceremony Manager
- 5-phase GenServer: `setup` -> `key_generated` -> `cert_bound` -> `custodians_assigned` -> `finalized`
- Multiple key managers (policy-driven) + auditor finalization
- Threshold Shamir secret sharing with per-custodian encrypted shares

### PkiCrypto Library
- Protocol-based algorithm dispatch (not behaviours/callbacks)
- Shared across CA and RA engines
- Modules: Algorithm, Registry, KDF, Symmetric (AES-256-GCM), Shamir, Attestation, KeyOps

### System Bootstrap
- First admin creation generates: user credentials + Keypair ACL + 4 system keypairs (root, sub_root, host signing, host cipher)
- Self-attestation for bootstrap admin, admin-attestation for subsequent users

### Other
- Consistent flat JSON API responses (no `%{data:}` wrappers)
- RA CertController with real issued-CSR queries and filters
- All portal HTTP clients fully wired (no stale stubs)
- STRAPTrust marketing landing page (EN/BM)
- 139 Playwright e2e tests + ~975 ExUnit tests

## Quick Start

```bash
# Clone
git -c http.sslVerify=false clone https://vcs.antrapol.tech:3800/Incubator/pki.git
cd pki
git config http.sslVerify false
git submodule update --init --recursive

# Configure
cp .env.example .env
# Edit .env — set strong passwords and secrets

# Build and start (8 containers)
podman-compose build
podman-compose up -d

# Run migrations
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiCaEngine.Release.migrate()"
podman exec pki-ra-engine bin/pki_ra_engine eval "PkiRaEngine.Release.migrate()"
podman exec pki-validation bin/pki_validation eval "PkiValidation.Release.migrate()"

# Verify
curl http://localhost:4001/health   # {"status":"ok"}
curl http://localhost:4003/health   # {"status":"ok"}
curl http://localhost:4005/health   # {"status":"ok"}
```

Then visit:
- `http://localhost:4006/login` — Platform Portal (tenant management)
- `http://localhost:4002/setup` — CA Portal (bootstrap first admin)
- `http://localhost:4004/setup` — RA Portal (bootstrap first admin)

## Key Features

- **Multi-Tenant** — Isolated databases per tenant with 4 schemas (ca/ra/validation/audit)
- **Cryptographic Credentials** — Dual signing + KEM keypairs per user, attested by admin
- **Key Ceremony** — Shamir threshold secret sharing (K-of-N custodians), auditor-finalized
- **Key Vault** — 3 protection modes for managed keypairs with signed grant envelopes
- **Certificate Signing** — X.509 certificate issuance with configurable profiles
- **OCSP/CRL** — Real-time certificate status with ETS cache
- **Attestation** — Public key attestation verified at every login
- **Audit Trail** — Tamper-evident logging with hash chains
- **HSM Support** — PKCS#11 interface (SoftHSM2 for dev, hardware HSM for production)
- **UUIDv7** — Time-sortable primary keys across all databases
- **REST API** — CSR submission, approval/rejection, certificate retrieval
- **Bootstrap** — First-run setup creates admin + ACL + system keypairs

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Elixir 1.18 / Erlang/OTP 27 |
| Web | Phoenix 1.8 + LiveView 1.1 |
| Database | PostgreSQL 17 (multi-tenant) |
| CSS | Tailwind CSS 4 + daisyUI 5 |
| Containers | Podman (rootless) |
| Crypto | PkiCrypto (protocol-based), Erlang `:crypto` + `:public_key` |
| KDF | PBKDF2 (310K iterations) + HKDF |
| Encryption | AES-256-GCM |
| Secret Sharing | Shamir (via KeyX) |
| HSM | PKCS#11 via SoftHSM2 |
| Reverse Proxy | Caddy (automatic HTTPS) |
| E2E Tests | Playwright |

## Project Structure

```
pki/
+-- compose.yml                  # Podman compose (8 services)
+-- .env.example                 # Environment template
+-- landing/                     # Marketing landing page (STRAPTrust)
+-- docs/
|   +-- deployment-guide.md      # Contabo VPS deployment guide
|   +-- hosting-sizing-guide.md  # Resource sizing (Tier 1-4)
|   +-- user-manual.md           # User manual with screenshots
|   +-- use-cases/               # 144 use cases across 4 docs
|   +-- superpowers/specs/       # Design specs
|   +-- superpowers/plans/       # Implementation plans
+-- e2e/                         # Playwright E2E tests (139 tests)
|   +-- tests/ca/                # CA Portal UI tests
|   +-- tests/ra/                # RA Portal UI tests
|   +-- tests/ca-api/            # CA Engine API tests
|   +-- tests/ra-api/            # RA Engine API tests
|   +-- tests/validation/        # OCSP/CRL tests
|   +-- tests/e2e/               # Cross-service flow tests
+-- softhsm2/                    # HSM container config
+-- src/
    +-- pki_crypto/              # Shared crypto library (protocol-based)
    +-- pki_platform_engine/     # Multi-tenant provisioner + resolver
    +-- pki_platform_portal/     # Tenant management portal
    +-- pki_ca_engine/           # CA Engine (OTP app)
    +-- pki_ca_portal/           # CA Portal (Phoenix LiveView)
    +-- pki_ra_engine/           # RA Engine (Plug REST API)
    +-- pki_ra_portal/           # RA Portal (Phoenix LiveView)
    +-- pki_validation/          # OCSP/CRL service
    +-- pki_audit_trail/         # Audit trail library
    +-- x509/                    # X.509 certificate library (submodule)
    +-- ex_ccrypto/              # Crypto abstractions (submodule)
    +-- keyx/                    # Key exchange library (submodule)
```

## Testing

```bash
# ExUnit (~975 tests)
for dir in pki_crypto pki_platform_engine pki_ca_engine pki_ra_engine pki_ca_portal pki_ra_portal pki_validation pki_platform_portal; do
  echo "=== $dir ==="
  (cd src/$dir && mix test)
done

# Playwright E2E (139 tests)
cd e2e && npm install && npx playwright install chromium
npx playwright test
```

## Documentation

- [Deployment Guide](docs/deployment-guide.md) — Contabo VPS + Caddy + straptrust.com
- [Hosting & Sizing Guide](docs/hosting-sizing-guide.md) — Resource planning (Tier 1-4)
- [User Manual](docs/user-manual.md) — Portal usage with screenshots
- [CA Use Cases](docs/use-cases/ca-use-cases.md) — 53 CA use cases
- [RA Use Cases](docs/use-cases/ra-use-cases.md) — 42 RA use cases
- [Platform Use Cases](docs/use-cases/platform-use-cases.md) — 8 platform use cases
- [E2E Use Cases](docs/use-cases/e2e-use-cases.md) — 21 cross-module use cases
- [Validation Use Cases](docs/use-cases/validation-use-cases.md) — 20 validation use cases
- [Beta.2 Design Spec](docs/superpowers/specs/2026-03-26-beta2-multi-tenancy-crypto-credentials.md)

## User Roles

**CA Portal:** CA Admin, Key Manager, RA Admin, Auditor

**RA Portal:** RA Admin, RA Officer, Auditor

**Platform Portal:** Platform Admin

## REST API

```bash
# Submit CSR
curl -X POST https://api.straptrust.com/api/v1/csr \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...", "cert_profile_id": "<uuid>"}'

# List issued certificates
curl https://api.straptrust.com/api/v1/certificates \
  -H "Authorization: Bearer <api-key>"

# Check certificate status (OCSP)
curl -X POST https://ocsp.straptrust.com/ocsp \
  -H "Content-Type: application/json" \
  -d '{"serial_number": "<serial>"}'

# Download CRL
curl https://ocsp.straptrust.com/crl
```

## Production Deployment

See the [Deployment Guide](docs/deployment-guide.md) for full instructions. Domains:

| Domain | Service |
|--------|---------|
| straptrust.com | Landing page |
| ca.straptrust.com | CA Portal |
| ra.straptrust.com | RA Portal |
| api.straptrust.com | RA Engine API |
| ocsp.straptrust.com | OCSP/CRL |
| admin.straptrust.com | Platform Portal |

## License

Proprietary — Antrapolation Technology Sdn Bhd. All rights reserved.
