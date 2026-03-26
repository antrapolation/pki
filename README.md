# PQC Certificate Authority System

A Post-Quantum Cryptography ready Certificate Authority infrastructure for issuing and managing digital certificates. Built for Malaysia's national PQC initiative.

**Developed by Antrapolation Technology Sdn Bhd**

## Supported Algorithms

| Algorithm | Type | Status |
|-----------|------|--------|
| **KAZ-SIGN** | Malaysia local PQC | Planned |
| **ML-DSA** (FIPS 204) | NIST PQC standard | Supported |
| **RSA-4096** | Classical | Supported |
| **ECC-P256/P384** | Classical | Supported |

## Architecture

```
                         Internet
                            │
                        ┌───▼───┐
                        │ Caddy │  HTTPS + Auto Let's Encrypt
                        └───┬───┘
            ┌───────────────┼───────────────┬──────────────┐
            │               │               │              │
      ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐  ┌────▼──────┐
      │ CA Portal │  │ RA Portal │  │ RA Engine │  │Validation │
      │   :4002   │  │   :4004   │  │   :4003   │  │   :4005   │
      └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └───────────┘
            │               │               │              ▲
            └──────┐        └──────┐        └──────┐       │
                   ▼               ▼               ▼       │
              ┌────────────────────────────────────────────┐
              │            CA Engine :4001                  │
              └────────────┬───────────────────────────────┘
                           │
                    ┌──────▼──────┐     ┌──────────────┐
                    │ PostgreSQL  │     │  SoftHSM2    │
                    └─────────────┘     └──────────────┘
```

| Service | Port | Purpose |
|---------|------|---------|
| CA Engine | 4001 | Core CA — key ceremonies, certificate signing, revocation |
| CA Portal | 4002 | Admin GUI for CA operations (Phoenix LiveView) |
| RA Engine | 4003 | Registration Authority — CSR processing, REST API |
| RA Portal | 4004 | Admin GUI for RA operations (Phoenix LiveView) |
| Validation | 4005 | OCSP responder + CRL publisher |
| PostgreSQL | 5432 | Shared database (4 databases) |
| SoftHSM2 | — | PKCS#11 HSM simulator |

## Quick Start

```bash
# Clone
git clone https://vcs.antrapol.tech:3800/Incubator/pki.git
cd pki

# Configure
cp .env.example .env
# Edit .env — set strong passwords and secrets

# Build and start
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

Then visit `http://localhost:4002/setup` (CA) and `http://localhost:4004/setup` (RA) to create admin accounts.

## Key Features

- **Key Ceremony** — Shamir threshold secret sharing (K-of-N custodians) for root key generation
- **Certificate Signing** — X.509 certificate issuance with configurable profiles
- **OCSP/CRL** — Real-time certificate status with cache invalidation on revocation
- **Audit Trail** — Tamper-evident logging with hash chains
- **HSM Support** — PKCS#11 interface (SoftHSM2 for dev, swap to real HSM for production)
- **UUIDv7** — Time-sortable primary keys across all databases (multi-tenancy ready)
- **REST API** — CSR submission, approval/rejection, certificate retrieval
- **Bootstrap** — First-run setup pages for initial admin account creation

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Elixir 1.18 / Erlang/OTP 27 |
| Web | Phoenix 1.8 + LiveView 1.1 |
| Database | PostgreSQL 16 |
| CSS | Tailwind CSS 4 + daisyUI 5 |
| Containers | Podman (rootless) |
| Crypto | Erlang `:public_key` + `:crypto`, X509 library |
| HSM | PKCS#11 via SoftHSM2 |
| E2E Tests | Playwright |

## Project Structure

```
pki/
├── compose.yml                  # Podman compose (7 services)
├── .env.example                 # Environment template
├── docs/
│   ├── deployment-guide.md      # VPS deployment guide
│   ├── user-manual.md           # User manual with screenshots
│   ├── screenshots/             # Portal screenshots
│   └── use-cases/               # Use case documentation
├── e2e/                         # Playwright E2E tests (110 tests)
│   ├── tests/ca/                # CA Portal tests
│   ├── tests/ra/                # RA Portal tests
│   ├── tests/ra-api/            # RA REST API tests
│   ├── tests/validation/        # OCSP/CRL tests
│   └── tests/e2e/               # Cross-service tests
├── softhsm2/                    # HSM container config
└── src/
    ├── pki_ca_engine/           # CA Engine (Elixir OTP app)
    ├── pki_ca_portal/           # CA Portal (Phoenix LiveView)
    ├── pki_ra_engine/           # RA Engine (Plug REST API)
    ├── pki_ra_portal/           # RA Portal (Phoenix LiveView)
    ├── pki_validation/          # OCSP/CRL service
    ├── pki_audit_trail/         # Audit trail library
    ├── x509/                    # X.509 certificate library
    ├── ex_ccrypto/              # Crypto abstractions
    └── keyx/                    # Key exchange library
```

## Testing

```bash
# ExUnit (648 tests)
for dir in pki_ca_engine pki_ra_engine pki_ca_portal pki_ra_portal pki_validation; do
  (cd src/$dir && mix test)
done

# Playwright E2E (110 tests)
cd e2e && npm install && npx playwright install chromium
ENGINE_CLIENT_MODE=mock podman-compose up -d
npx playwright test
```

## Documentation

- [Deployment Guide](docs/deployment-guide.md) — Ubuntu VPS + Caddy deployment
- [User Manual](docs/user-manual.md) — Portal usage with screenshots
- [CA Use Cases](docs/use-cases/ca-use-cases.md) — 35 CA module use cases
- [RA Use Cases](docs/use-cases/ra-use-cases.md) — 38 RA module use cases
- [Validation Use Cases](docs/use-cases/validation-use-cases.md) — 20 validation use cases
- [E2E Use Cases](docs/use-cases/e2e-use-cases.md) — 16 cross-module use cases

## User Roles

**CA Portal:** CA Admin, Key Manager, Auditor

**RA Portal:** RA Admin, RA Officer, Auditor

## REST API

```bash
# Submit CSR
curl -X POST https://api.yourdomain.com/api/v1/csr \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...", "cert_profile_id": "<uuid>"}'

# Check certificate status (OCSP)
curl -X POST https://ocsp.yourdomain.com/ocsp \
  -H "Content-Type: application/json" \
  -d '{"serial_number": "<serial>"}'

# Download CRL
curl https://ocsp.yourdomain.com/crl
```

## License

Proprietary — Antrapolation Technology Sdn Bhd. All rights reserved.
