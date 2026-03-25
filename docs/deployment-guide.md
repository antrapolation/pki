# PQC Certificate Authority System — Deployment Guide

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Podman | 4.0+ | Container runtime |
| podman-compose | 1.0+ | Multi-container orchestration |
| Elixir | 1.18+ | Build from source (optional if using containers) |
| Erlang/OTP | 27+ | Runtime (embedded in container images) |
| PostgreSQL | 16+ | Provided via container |

Check your environment:

```bash
podman --version
podman-compose --version
```

If `podman-compose` is not installed:

```bash
pip3 install podman-compose
```

---

## Quick Start (Development)

### 1. Clone and configure

```bash
git clone <repo-url> pki
cd pki
cp .env.example .env   # Edit .env to set passwords and secrets
```

### 2. Start all services

```bash
podman-compose up -d
```

This starts 7 containers:

| Service | Container | Port | Description |
|---------|-----------|------|-------------|
| PostgreSQL | pki-postgres | 5434 | Shared database (4 databases auto-created) |
| SoftHSM2 | pki-softhsm2 | — | PKCS#11 HSM simulator for key operations |
| CA Engine | pki-ca-engine | 4001 | Core CA — signing keys, ceremonies, certificate issuance |
| CA Portal | pki-ca-portal | 4002 | CA Admin GUI (Phoenix LiveView) |
| RA Engine | pki-ra-engine | 4003 | Registration Authority — CSR processing, REST API |
| RA Portal | pki-ra-portal | 4004 | RA Admin GUI (Phoenix LiveView) |
| Validation | pki-validation | 4005 | OCSP responder + CRL publisher |

### 3. Run database migrations

```bash
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiCaEngine.Release.migrate()"
podman exec pki-ra-engine bin/pki_ra_engine eval "PkiRaEngine.Release.migrate()"
podman exec pki-validation bin/pki_validation eval "PkiValidation.Release.migrate()"
```

### 4. Verify services are running

```bash
podman ps --filter "name=pki" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 5. Bootstrap admin accounts

On first run, both portals require initial admin setup:

1. **CA Portal**: Navigate to http://localhost:4002/setup
   - Create the first CA Admin account (username + password)
   - This page is only accessible when no users exist in the database
   - After setup, you'll be redirected to the login page

2. **RA Portal**: Navigate to http://localhost:4004/setup
   - Create the first RA Admin account
   - Same first-run-only behavior

3. **Login**: Navigate to `/login` on either portal
   - Enter username and password created during setup
   - Sessions are encrypted and signed (Argon2 password hashing)

### 6. Verify SoftHSM2

```bash
# Show HSM slots
podman exec pki-softhsm2 softhsm2-util --show-slots

# Verify CA engine can see the HSM library
podman exec pki-ca-engine ls -la /hsm/lib/libsofthsm2.so

# List objects on token
podman exec pki-softhsm2 pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label PkiCA --pin 1234 --list-objects
```

### 7. Stop all services

```bash
podman-compose down
```

To remove volumes (wipes all data including HSM tokens and user accounts):

```bash
podman-compose down -v
```

---

## Environment Configuration

All secrets and credentials are sourced from a `.env` file (not committed to git). Copy `.env.example` and configure:

```bash
cp .env.example .env
```

### `.env` file contents

```bash
# PostgreSQL
POSTGRES_USER=postgres
POSTGRES_PASSWORD=CHANGE_ME_strong_password_here

# SoftHSM2 (dev only — replace with real HSM config in production)
SOFTHSM_TOKEN_LABEL=PkiCA
SOFTHSM_SO_PIN=CHANGE_ME_8_digit_so_pin
SOFTHSM_USER_PIN=CHANGE_ME_user_pin

# Session signing — generate with: openssl rand -base64 64
SECRET_KEY_BASE=CHANGE_ME_generate_with_openssl_rand_base64_64
```

Generate a strong `SECRET_KEY_BASE`:

```bash
openssl rand -base64 64
# or
mix phx.gen.secret
```

---

## Authentication

### Bootstrap Flow (First Run)

```
First visit → /setup (only when 0 users in DB)
  ├── Enter username, display name, password
  ├── Creates admin account (ca_admin or ra_admin)
  └── Redirects to /login

Subsequent visits → /login
  ├── Username + password
  ├── Validated against Argon2 hash in DB
  └── Encrypted session cookie set
```

### Security Features

- **Password hashing**: Argon2id (timing-safe, memory-hard)
- **Session cookies**: Signed + encrypted, HttpOnly, SameSite=Strict, Secure
- **Bootstrap protection**: `/setup` returns 404 after first user created (transaction-guarded against race conditions)
- **CSRF protection**: Phoenix CSRF tokens on all forms

### User Roles

**CA Portal:**
| Role | Permissions |
|------|-------------|
| `ca_admin` | Manage admins, auditors, view audit log |
| `key_manager` | Manage keystores, keys, ceremonies, keypair access |
| `auditor` | View audit log, participate in ceremonies |

**RA Portal:**
| Role | Permissions |
|------|-------------|
| `ra_admin` | Manage users, cert profiles, service configs, API keys |
| `ra_officer` | Process CSRs (view, approve, reject) |
| `auditor` | View audit log |

---

## HSM Configuration

### Architecture

SoftHSM2 runs as a separate container. The CA engine accesses it via shared volumes — the PKCS#11 library and token storage are mounted read-only.

```
┌──────────────────────┐     ┌─────────────────────────┐
│  pki-softhsm2        │     │  pki-ca-engine           │
│                      │     │                          │
│  softhsm2 + opensc   │     │  PKCS11_LIB_PATH=/hsm/  │
│  Token: "PkiCA"      │     │    lib/libsofthsm2.so   │
│  PIN: from .env      │     │  SOFTHSM2_CONF=/hsm/    │
│                      │     │    softhsm2.conf         │
│  /var/lib/softhsm/ ──┼─vol─┼→ /hsm/tokens/ (ro)      │
│    tokens/           │     │                          │
│  /shared/lib/ ───────┼─vol─┼→ /hsm/lib/ (ro)         │
│    libsofthsm2.so    │     │                          │
└──────────────────────┘     └─────────────────────────┘
```

### HSM Environment Variables (CA Engine)

| Variable | Default | Description |
|----------|---------|-------------|
| `PKCS11_LIB_PATH` | `/hsm/lib/libsofthsm2.so` | Path to PKCS#11 library |
| `HSM_SLOT` | `0` | HSM slot ID |
| `HSM_PIN` | from `.env` | User PIN for crypto operations |
| `HSM_TOKEN_LABEL` | `PkiCA` | Token label |
| `SOFTHSM2_CONF` | `/hsm/softhsm2.conf` | SoftHSM2 config path (dev only) |

### Swapping to a Real HSM (Production)

Only change environment variables on `pki-ca-engine` — no code changes required. The system uses standard PKCS#11, which all HSM vendors implement.

```bash
# Thales Luna Network HSM
PKCS11_LIB_PATH=/usr/lib/libCryptoki2_64.so
HSM_SLOT=0
HSM_PIN=<ceremony-pin>

# AWS CloudHSM
PKCS11_LIB_PATH=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so
HSM_SLOT=1
HSM_PIN=<cu_user>:<password>
```

When using a real HSM, remove the `softhsm2` service, its volumes (`softhsm-tokens`, `softhsm-lib`), and the `SOFTHSM2_CONF` env var from compose.yml. Mount the vendor's PKCS#11 library from the host instead.

### SoftHSM2 Admin Commands

```bash
# Generate a test RSA key on HSM
podman exec pki-softhsm2 pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label PkiCA --pin 1234 --keypairgen --key-type rsa:2048 --label "test-rsa"

# Generate a test EC key on HSM
podman exec pki-softhsm2 pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label PkiCA --pin 1234 --keypairgen --key-type EC:secp256r1 --label "test-ec"

# List all objects
podman exec pki-softhsm2 pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label PkiCA --pin 1234 --list-objects

# Reset token (destroys all keys)
podman exec pki-softhsm2 softhsm2-util --delete-token --token PkiCA
podman exec pki-softhsm2 softhsm2-util --init-token --free --label PkiCA \
  --so-pin 12345678 --pin 1234
```

---

## Local Development (Without Containers)

### 1. Start PostgreSQL via Podman

```bash
podman run -d \
  --name pki-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  docker.io/library/postgres:16-alpine
```

### 2. Create databases

```bash
podman exec pki-postgres psql -U postgres -c "CREATE DATABASE pki_ca_engine;"
podman exec pki-postgres psql -U postgres -c "CREATE DATABASE pki_ra_engine;"
podman exec pki-postgres psql -U postgres -c "CREATE DATABASE pki_validation;"
podman exec pki-postgres psql -U postgres -c "CREATE DATABASE pki_audit_trail;"
```

### 3. Setup each service

```bash
# CA Engine
cd src/pki_ca_engine
mix deps.get && mix ecto.setup
mix test  # verify: 178 tests, 0 failures

# RA Engine
cd ../pki_ra_engine
mix deps.get && mix ecto.setup
mix test  # verify: 133 tests, 0 failures

# Validation
cd ../pki_validation
mix deps.get && mix ecto.setup
mix test  # verify: 54 tests, 0 failures

# CA Portal (no database)
cd ../pki_ca_portal
mix deps.get
mix test  # verify: 65 tests, 0 failures

# RA Portal (no database)
cd ../pki_ra_portal
mix deps.get
mix test  # verify: 70 tests, 0 failures

# Audit Trail
cd ../pki_audit_trail
mix deps.get && mix ecto.setup
mix test  # verify: 31 tests, 0 failures
```

### 4. Run services

Start each in a separate terminal:

```bash
# Terminal 1: CA Engine
cd src/pki_ca_engine && mix run --no-halt

# Terminal 2: RA Engine
cd src/pki_ra_engine && iex -S mix

# Terminal 3: CA Portal
cd src/pki_ca_portal && mix phx.server

# Terminal 4: RA Portal
cd src/pki_ra_portal && mix phx.server

# Terminal 5: Validation
cd src/pki_validation && mix run --no-halt
```

---

## Production Deployment

### Architecture Options

#### Minimal (Single Server)

All services on one machine. Suitable for testing, small organizations.

```
┌──────────────────────────────────────┐
│          Single Server               │
│                                      │
│  pki-softhsm2  (or real HSM)        │
│  pki-ca-engine          :4001        │
│  pki-ca-portal          :4002        │
│  pki-ra-engine          :4003        │
│  pki-ra-portal          :4004        │
│  pki-validation         :4005        │
│  postgres               :5432        │
│                                      │
│  Nginx (TLS termination) :443        │
└──────────────────────────────────────┘
```

#### Standard (3+ Servers)

CA engine isolated on dedicated server with HSM. Recommended for government/enterprise.

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   CA Server       │  │   App Server      │  │  Validation      │
│   (secured, HSM)  │  │                   │  │  (DMZ)           │
│                   │  │                   │  │                  │
│  Real HSM / SoftHSM│  │  pki-ca-portal    │  │  pki-validation  │
│  pki-ca-engine    │  │  pki-ra-portal    │  │  (N instances)   │
│                   │  │  pki-ra-engine    │  │                  │
└───────┬──────────┘  └───────┬──────────┘  └───────┬──────────┘
        │                     │                      │
        └─────────┬───────────┘                      │
                  │                                  │
         ┌───────┴──────────┐               ┌───────┴──────┐
         │  PostgreSQL HA    │               │  PostgreSQL   │
         │  (primary+replica)│               │  (read replica)│
         └──────────────────┘               └──────────────┘
```

### Building Container Images

```bash
# Build all images
podman-compose build

# Or build individually
podman build -t pki-ca-engine:latest   -f src/pki_ca_engine/Containerfile .
podman build -t pki-ra-engine:latest   -f src/pki_ra_engine/Containerfile .
podman build -t pki-ca-portal:latest   -f src/pki_ca_portal/Containerfile .
podman build -t pki-ra-portal:latest   -f src/pki_ra_portal/Containerfile .
podman build -t pki-validation:latest  -f src/pki_validation/Containerfile .
podman build -t pki-softhsm2:latest    ./softhsm2/
```

### Environment Variables

#### All Services

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY_BASE` | Yes (prod) | — | 64+ byte secret for session signing (from `.env`) |
| `RELEASE_DISTRIBUTION` | No | `name` | Erlang distribution mode |
| `RELEASE_NODE` | No | `<app>@<hostname>` | Erlang node name |

#### Database Services (CA Engine, RA Engine, Validation)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes (prod) | — | `ecto://USER:PASS@HOST:PORT/DATABASE` |
| `POOL_SIZE` | No | `10` | Database connection pool size |

#### Web Services (Portals)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `4000` | HTTP listen port |
| `PHX_HOST` | Yes (prod) | — | Public hostname for URL generation |
| `PHX_SERVER` | Yes (prod) | — | Set to `true` to start HTTP server |

### TLS Configuration

#### Nginx Reverse Proxy (Recommended)

```nginx
# /etc/nginx/sites-available/pki-ca-portal
server {
    listen 443 ssl http2;
    server_name ca.pki.example.com;

    ssl_certificate     /etc/letsencrypt/live/ca.pki.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ca.pki.example.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        proxy_pass http://127.0.0.1:4002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Repeat for each portal/service with appropriate server_name and proxy_pass port
```

#### Let's Encrypt Certificates

```bash
certbot --nginx -d ca.pki.example.com -d ra.pki.example.com -d ocsp.pki.example.com
```

### Database Setup (Production)

#### Separate PostgreSQL Instances (Recommended for High Security)

```bash
# CA Engine database
podman run -d --name pki-ca-db \
  -e POSTGRES_USER=pki_ca \
  -e POSTGRES_PASSWORD=<strong-password> \
  -e POSTGRES_DB=pki_ca_engine \
  -v pki-ca-data:/var/lib/postgresql/data \
  -p 5433:5432 \
  docker.io/library/postgres:16-alpine

# RA Engine database
podman run -d --name pki-ra-db \
  -e POSTGRES_USER=pki_ra \
  -e POSTGRES_PASSWORD=<strong-password> \
  -e POSTGRES_DB=pki_ra_engine \
  -v pki-ra-data:/var/lib/postgresql/data \
  -p 5434:5432 \
  docker.io/library/postgres:16-alpine
```

#### Run Migrations

```bash
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiCaEngine.Release.migrate()"
podman exec pki-ra-engine bin/pki_ra_engine eval "PkiRaEngine.Release.migrate()"
podman exec pki-validation bin/pki_validation eval "PkiValidation.Release.migrate()"
```

### Running in Production

#### Podman Rootless (Recommended for VPS)

```bash
podman run -d \
  --name pki-ca-engine \
  --restart=always \
  -p 127.0.0.1:4001:4001 \
  -v softhsm-tokens:/hsm/tokens:ro \
  -v softhsm-lib:/hsm/lib:ro \
  --env-file /etc/pki/ca-engine.env \
  --memory=1g \
  --cpus=2 \
  pki-ca-engine:latest
```

#### Systemd Units (Bare Metal)

```ini
# /etc/systemd/system/pki-ca-engine.service
[Unit]
Description=PKI CA Engine
After=network.target postgresql.service

[Service]
Type=exec
User=pki
Group=pki
WorkingDirectory=/opt/pki/ca-engine
ExecStart=/opt/pki/ca-engine/bin/pki_ca_engine start
ExecStop=/opt/pki/ca-engine/bin/pki_ca_engine stop
Restart=on-failure
RestartSec=5
Environment=HOME=/opt/pki
EnvironmentFile=/etc/pki/ca-engine.env

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/pki/ca-engine.env
DATABASE_URL=ecto://pki_ca:password@localhost:5433/pki_ca_engine
SECRET_KEY_BASE=<generated-secret>
PKCS11_LIB_PATH=/usr/lib/libCryptoki2_64.so
HSM_SLOT=0
HSM_PIN=<ceremony-pin>
RELEASE_DISTRIBUTION=name
RELEASE_NODE=pki_ca_engine@ca.pki.internal
```

---

## Operations

### Health Checks

```bash
# All services
podman ps --filter "name=pki" --format "table {{.Names}}\t{{.Status}}"

# Portal check (returns HTML)
curl -s -o /dev/null -w "%{http_code}" http://localhost:4002
curl -s -o /dev/null -w "%{http_code}" http://localhost:4004

# HSM health
podman exec pki-softhsm2 softhsm2-util --show-slots
```

### Logs

```bash
# Container logs
podman logs pki-ca-engine
podman logs pki-ra-engine --follow

# All services
podman-compose logs -f
```

### Database Backups

```bash
# Backup all databases
for db in pki_ca_engine pki_ra_engine pki_validation pki_audit_trail; do
  podman exec pki-postgres pg_dump -U postgres $db > backup_${db}_$(date +%Y%m%d).sql
done
```

### OCSP Testing

```bash
# Check certificate status
curl -X POST http://localhost:4005/ocsp \
  -H "Content-Type: application/json" \
  -d '{"serial_number": "abc123"}'

# Get current CRL
curl http://localhost:4005/crl
```

### RA Engine REST API

```bash
# Submit a CSR
curl -X POST http://localhost:4003/api/v1/csr \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...", "cert_profile_id": 1}'

# List CSRs
curl http://localhost:4003/api/v1/csr \
  -H "Authorization: Bearer <api-key>"

# Approve a CSR
curl -X POST http://localhost:4003/api/v1/csr/1/approve \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"reviewer_user_id": 1}'
```

---

## Running Tests

### Unit Tests (All Services)

```bash
# From project root — run all 446 tests
for dir in pki_audit_trail pki_ca_engine pki_ra_engine pki_ca_portal pki_ra_portal pki_validation; do
  echo "=== $dir ==="
  (cd src/$dir && mix test)
done
```

### E2E Tests (Playwright)

```bash
cd e2e
npm install
npx playwright install chromium

# Run all E2E tests (requires services running)
npm test

# Run by module
npm run test:ca           # CA Portal UI
npm run test:ra           # RA Portal UI
npm run test:api          # RA REST API
npm run test:validation   # OCSP/CRL
npm run test:e2e          # Cross-module flows

# View HTML report
npm run report
```

### Test Requirements

- PostgreSQL running on `localhost:5432` (user: `postgres`, password: `postgres`)
- Test databases created: `pki_ca_engine_test`, `pki_ra_engine_test`, `pki_validation_test`, `pki_audit_trail_test`

Quick setup:

```bash
podman run -d --name pki-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  docker.io/library/postgres:16-alpine
```

---

## Troubleshooting

### Podman Machine Issues (macOS)

```bash
# Restart Podman machine
podman machine stop && podman machine start

# Check machine status
podman machine info
```

### Database Connection Refused

```bash
# Verify Postgres is running and healthy
podman exec pki-postgres pg_isready -U postgres

# Check databases exist
podman exec pki-postgres psql -U postgres -l

# Check DATABASE_URL is set correctly inside container
podman exec pki-ca-engine printenv DATABASE_URL
```

### Port Conflicts

The default postgres port (5434) avoids conflicts with local PostgreSQL. If other ports conflict:

```bash
# Check what's using a port
lsof -i :4001
```

### Container Using Old Image

If `podman-compose up -d` uses a stale image after rebuilding:

```bash
podman-compose down
podman-compose build <service-name>
podman-compose up -d
```

### Bootstrap Setup Not Showing

If `/setup` redirects to `/login`, it means a user already exists in the database. To reset:

```bash
# Reset the database (destroys all data)
podman-compose down -v
podman-compose up -d
# Re-run migrations, then visit /setup again
```

### HSM Token Not Found

```bash
# Verify token directory is shared
podman exec pki-ca-engine ls /hsm/tokens/

# Verify SoftHSM2 config
podman exec pki-ca-engine cat /hsm/softhsm2.conf

# Check HSM env vars
podman exec pki-ca-engine printenv | grep -E "PKCS11|HSM|SOFTHSM"
```

### Container Build Failures

```bash
# Build with verbose output
podman build --no-cache -t pki-ca-engine:latest -f src/pki_ca_engine/Containerfile . 2>&1 | tee build.log

# Check Elixir/OTP version compatibility
podman run --rm docker.io/hexpm/elixir:1.18.4-erlang-27.3.4.6-debian-trixie-20260223 elixir --version
```

---

## Service Ports Summary

| Port | Service | Protocol | Access |
|------|---------|----------|--------|
| 4001 | CA Engine | Erlang RPC | Internal only |
| 4002 | CA Portal | HTTP (LiveView) | Admin users via Nginx |
| 4003 | RA Engine | HTTP/JSON (REST API) | External clients + Admin via Nginx |
| 4004 | RA Portal | HTTP (LiveView) | Admin users via Nginx |
| 4005 | Validation | HTTP/JSON (OCSP/CRL) | Public via Nginx |
| 5434 | PostgreSQL | PostgreSQL | Internal only |

---

## Security Checklist (Production)

- [ ] Copy `.env.example` to `.env` and change ALL default values
- [ ] Generate unique `SECRET_KEY_BASE` per service (`openssl rand -base64 64`)
- [ ] Set strong PostgreSQL passwords (not `postgres/postgres`)
- [ ] Set strong HSM PINs (not `1234` / `12345678`)
- [ ] Use separate PostgreSQL instances (or at minimum separate users) per database
- [ ] Enable TLS on all external-facing endpoints (Nginx or direct)
- [ ] Restrict CA Engine port (4001) to internal network only
- [ ] Restrict PostgreSQL port to internal network only
- [ ] Configure firewall rules (UFW/iptables) per deployment topology
- [ ] Session cookies are signed + encrypted (already configured)
- [ ] Enable Erlang Distribution TLS (`inet_tls_dist`) for inter-node communication
- [ ] Sign container images with `cosign` before deployment
- [ ] Set up automated database backups
- [ ] Configure audit trail chain verification as a periodic health check
- [ ] Review and restrict Podman container resource limits (memory, CPU)
- [ ] Swap SoftHSM2 for a real HSM (Thales Luna, AWS CloudHSM, etc.)
- [ ] Mount HSM token storage as read-only from CA engine
- [ ] Add rate limiting on `/login` and `/setup` endpoints (`PlugAttack` or `Hammer`)
- [ ] Never commit `.env` to version control (already in `.gitignore`)
