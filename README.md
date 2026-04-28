# STRAPTrust — Post-Quantum Certificate Authority

A Post-Quantum Cryptography ready Certificate Authority infrastructure for issuing and managing digital certificates. Built for Malaysia's national PQC initiative.

**Product of [Antrapolation Technology Sdn Bhd](https://antrapol.com)**

**Latest release:** [v1.0.0-beta.3](https://vcs.antrapol.tech:3800/Incubator/pki/releases/tag/v1.0.0-beta.3)

## Supported Algorithms

| Algorithm | Type | Status |
|-----------|------|--------|
| **KAZ-SIGN** | Malaysia local PQC | Supported (via liboqs NIF) |
| **ML-DSA** (FIPS 204) | NIST PQC standard | Supported |
| **SLH-DSA** | NIST PQC hash-based | Supported |
| **ML-KEM** | NIST PQC key encapsulation | Supported |
| **RSA-4096** | Classical signing | Supported |
| **ECC-P256/P384** | Classical signing | Supported |
| **ECDH-P256** | Key Encapsulation (KEM) | Supported |

## Architecture

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

| Component | Purpose |
|-----------|---------|
| pki_platform | Platform portal + tenant lifecycle; Caddy routes `admin.*` here |
| pki_tenant | Per-tenant BEAM — CA engine, RA engine, OCSP/CRL, CA/RA portal UI |
| PostgreSQL | Platform-only: tenant registry, platform users, platform audit trail |
| Mnesia | Per-tenant state: keys, certificates, certificate status, CRL data |
| SoftHSM2 / HSM | PKCS#11 key storage for CA signing keys |

## What's New (since beta.2)

### Post-Quantum Crypto via liboqs NIF
- **pki_oqs_nif** — Elixir NIF bindings to liboqs for KAZ-SIGN, SLH-DSA, ML-KEM
- Full CSR lifecycle with KAZ-SIGN NIF — integration tested end-to-end
- Key activation and signing with post-quantum algorithms

### Streamlined Tenant Onboarding
- **Tenant admin role** — scoped access per tenant (separate from platform_admin)
- Single-form tenant wizard with live provisioning progress
- CA/RA setup routes removed — users created exclusively via Platform Portal
- Role-based sidebar navigation and route scoping

### Production Hardening
- **Single-node Direct mode** — run all services in one BEAM node for simpler deployments
- Telemetry metrics and structured JSON logging
- Session hardening and error sanitization for safe production responses
- P0+P1 production hardening from readiness assessment
- `check_origin: false` for flexible reverse-proxy deployment

### RA Engine — Phases C & D
- **Webhook delivery** — CSR and certificate lifecycle event notifications with persistence
- **API key redesign** — approval mode, validation endpoints
- **Domain Control Validation (DCV)** — challenge-based domain ownership verification
- Service config improvements

### Auditor Witness
- Auditor finalization in key ceremonies — witness role for ceremony completion

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

# Start dev infrastructure (PostgreSQL + SoftHSM2)
podman compose -f dev-infra.yml up -d

# Run migrations (in order)
cd src/pki_platform_engine && mix ecto.create && mix ecto.migrate && cd ../..
cd src/pki_ca_engine && mix ecto.create && mix ecto.migrate && cd ../..
cd src/pki_ra_engine && mix ecto.create && mix ecto.migrate && cd ../..
cd src/pki_validation && mix ecto.create && mix ecto.migrate && cd ../..

# Start services (all run in one BEAM node)
cd src/pki_platform_portal && mix phx.server  # :4006
cd src/pki_ca_portal && mix phx.server         # :4002
cd src/pki_ra_portal && mix phx.server         # :4004
```

Then visit:
- `http://localhost:4006/setup` — Platform Portal (create platform admin, then tenants)
- `http://localhost:4002` — CA Portal
- `http://localhost:4004` — RA Portal

## Key Features

- **Multi-Tenant** — Isolated databases per tenant with 4 schemas (ca/ra/validation/audit)
- **Post-Quantum Crypto** — KAZ-SIGN, ML-DSA, SLH-DSA, ML-KEM via liboqs NIF bindings
- **Cryptographic Credentials** — Dual signing + KEM keypairs per user, attested by admin
- **Key Ceremony** — Shamir threshold secret sharing (K-of-N custodians), auditor-finalized
- **Key Vault** — 3 protection modes for managed keypairs with signed grant envelopes
- **Certificate Signing** — X.509 certificate issuance with configurable profiles
- **Domain Control Validation** — Challenge-based DCV for domain ownership verification
- **OCSP/CRL** — Real-time certificate status with ETS cache
- **Webhook Delivery** — CSR and certificate lifecycle event notifications
- **Attestation** — Public key attestation verified at every login
- **Audit Trail** — Tamper-evident logging with hash chains (WAL-buffered)
- **HSM Support** — PKCS#11 interface (SoftHSM2 for dev, hardware HSM for production)
- **Tenant Onboarding** — Wizard-driven provisioning with tenant_admin role scoping
- **UUIDv7** — Time-sortable primary keys across all databases
- **REST API** — CSR submission, approval/rejection, certificate retrieval, DCV
- **Telemetry** — Metrics and structured JSON logging for production observability
- **Direct Mode** — Single-node deployment for simpler infrastructure

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Elixir 1.18 / Erlang/OTP 27 |
| Web | Phoenix 1.8 + LiveView 1.1 |
| Database | PostgreSQL 17 (multi-tenant) |
| CSS | Tailwind CSS 4 + daisyUI 5 |
| Containers | Podman (rootless) |
| PQC | pki_oqs_nif (liboqs NIF bindings) |
| Crypto | PkiCrypto (protocol-based), Erlang `:crypto` + `:public_key` |
| KDF | PBKDF2 (310K iterations) + HKDF |
| Encryption | AES-256-GCM |
| Secret Sharing | Shamir (via KeyX) |
| HSM | PKCS#11 via SoftHSM2 |
| Reverse Proxy | Caddy (automatic HTTPS) |
| E2E Tests | Playwright |
| Telemetry | Telemetry + Logger JSON |

## Project Structure

```
pki/
+-- Caddyfile                    # Reverse proxy config (HTTPS + security headers)
+-- dev-infra.yml                # Dev infrastructure (PostgreSQL + SoftHSM2)
+-- dev.sh                       # Dev startup script
+-- .env.example                 # Environment template
+-- landing/                     # Marketing landing page (STRAPTrust EN/BM)
+-- scripts/
|   +-- init-databases.sh        # PostgreSQL multi-tenant init
|   +-- integration_test.exs     # Full CSR lifecycle integration test
+-- docs/
|   +-- deployment-guide.md      # Production deployment (Caddy + Direct mode)
|   +-- hosting-sizing-guide.md  # Resource sizing (Tier 1-4)
|   +-- user-manual.md           # CA/RA portal usage with screenshots
|   +-- platform-portal-user-manual.md  # Platform admin manual
|   +-- webhook-reference.md     # Webhook delivery reference
|   +-- use-cases/               # 144 use cases across 5 docs
|   +-- superpowers/specs/       # 16 design specs
|   +-- superpowers/plans/       # Implementation plans
|   +-- v1.0.0-beta.3/           # Beta.3 roadmap (multi-CA, BEAM clustering)
+-- e2e/                         # Playwright E2E tests (35 spec files, 121 tests)
|   +-- tests/ca/                # CA Portal UI tests
|   +-- tests/ra/                # RA Portal UI tests
|   +-- tests/ca-api/            # CA Engine API tests
|   +-- tests/ra-api/            # RA Engine API tests
|   +-- tests/validation/        # OCSP/CRL tests
|   +-- tests/e2e/               # Cross-service flow tests
+-- softhsm2/                    # SoftHSM2 container config
+-- src/
    +-- pki_crypto/              # Shared crypto library (protocol-based)
    +-- pki_oqs_nif/             # liboqs NIF bindings (KAZ-SIGN, SLH-DSA, ML-KEM)
    +-- pki_platform_engine/     # Multi-tenant provisioner + resolver
    +-- pki_platform_portal/     # Tenant & user management portal
    +-- pki_ca_engine/           # CA Engine (OTP app)
    +-- pki_ca_portal/           # CA Portal (Phoenix LiveView)
    +-- pki_ra_engine/           # RA Engine (Plug REST API)
    +-- pki_ra_portal/           # RA Portal (Phoenix LiveView)
    +-- pki_validation/          # OCSP/CRL service
    +-- pki_audit_trail/         # Audit trail library (WAL-buffered, hash-chained)
    +-- x509/                    # X.509 certificate library (submodule)
    +-- ex_ccrypto/              # Crypto abstractions (submodule)
    +-- keyx/                    # Key exchange + Shamir library (submodule)
    +-- strap_ciphagile/         # Cipher agility framework (submodule)
    +-- ap_java_crypto/          # Java cryptography bridge (submodule)
    +-- strap_*_provider/        # Keystore provider plugins (submodules)
    +-- strap_proc_reg/          # Process registry (submodule)
    +-- ex_jruby_port/           # JRuby port bridge (submodule)
```

## Testing

```bash
# ExUnit (~1725 tests across all packages)
for dir in pki_crypto pki_oqs_nif pki_audit_trail pki_platform_engine pki_ca_engine pki_ra_engine pki_ca_portal pki_ra_portal pki_validation pki_platform_portal; do
  echo "=== $dir ==="
  (cd src/$dir && mix test)
done

# Playwright E2E (121 tests across 35 spec files)
cd e2e && npm install && npx playwright install chromium
npx playwright test
```

## Documentation

- [Deployment Guide](docs/deployment-guide.md) — Production deployment with Caddy + Direct mode
- [Hosting & Sizing Guide](docs/hosting-sizing-guide.md) — Resource planning (Tier 1-4)
- [User Manual](docs/user-manual.md) — CA/RA portal usage with screenshots
- [Platform Portal Manual](docs/platform-portal-user-manual.md) — Tenant & user management
- [Webhook Reference](docs/webhook-reference.md) — CSR/cert lifecycle webhook delivery
- [CA Use Cases](docs/use-cases/ca-use-cases.md) — 53 CA use cases
- [RA Use Cases](docs/use-cases/ra-use-cases.md) — 42 RA use cases
- [Platform Use Cases](docs/use-cases/platform-use-cases.md) — 8 platform use cases
- [E2E Use Cases](docs/use-cases/e2e-use-cases.md) — 21 cross-module use cases
- [Validation Use Cases](docs/use-cases/validation-use-cases.md) — 20 validation use cases

## User Roles

**Platform Portal:** Platform Admin, Tenant Admin

**CA Portal:** CA Admin, Key Manager, Auditor

**RA Portal:** RA Admin, RA Officer, Auditor

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

# Domain Control Validation
curl -X POST https://api.straptrust.com/api/v1/dcv/challenge \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "method": "dns"}'
```

## Production Deployment

See the [Deployment Guide](docs/deployment-guide.md) for full instructions. Supports two modes:

- **Direct mode** — Single-node BEAM deployment (simpler, for smaller installations)
- **Distributed mode** — Multi-node with Caddy reverse proxy

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
