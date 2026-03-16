# PQC Certificate Authority System — Deployment Guide

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Podman | 4.0+ | Container runtime |
| podman-compose | 1.0+ | Multi-container orchestration |
| Elixir | 1.15+ | Build from source (optional if using containers) |
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

### 1. Clone the repository

```bash
git clone <repo-url> pki
cd pki
```

### 2. Start all services

```bash
podman-compose up -d
```

This starts 7 containers:

| Service | Container | Port | Description |
|---------|-----------|------|-------------|
| PostgreSQL | pki-postgres | 5432 | Shared database (4 databases auto-created) |
| SSDID Registry | pki-ssdid-registry | 4000 | DID Document resolution |
| CA Engine | pki-ca-engine | 4001 | Core CA — signing keys, ceremonies |
| CA Portal | pki-ca-portal | 4002 | CA Admin GUI (Phoenix LiveView) |
| RA Engine | pki-ra-engine | 4003 | Registration Authority — CSR processing, REST API |
| RA Portal | pki-ra-portal | 4004 | RA Admin GUI (Phoenix LiveView) |
| Validation | pki-validation | 4005 | OCSP responder + CRL publisher |

### 3. Verify services are running

```bash
podman-compose ps
```

Check health endpoints:

```bash
curl http://localhost:4000/api/registry/info   # SSDID Registry
curl http://localhost:4003/health              # RA Engine REST API
curl http://localhost:4005/health              # Validation (OCSP/CRL)
```

### 4. Access the portals

| Portal | URL | Purpose |
|--------|-----|---------|
| CA Admin | http://localhost:4002 | Manage CA engine, key ceremonies, users |
| RA Admin | http://localhost:4004 | Manage CSRs, cert profiles, API keys |

Login with any DID and role (development mode — no credential verification).

### 5. Stop all services

```bash
podman-compose down
```

To remove volumes (wipes all data):

```bash
podman-compose down -v
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
# Audit Trail
cd src/pki_audit_trail
mix deps.get && mix ecto.setup
mix test  # verify: 31 tests, 0 failures

# CA Engine
cd ../pki_ca_engine
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
┌─────────────────────────────────┐
│          Single Server          │
│                                 │
│  pki-ca-engine     :4001        │
│  pki-ca-portal     :4002        │
│  pki-ra-engine     :4003        │
│  pki-ra-portal     :4004        │
│  pki-validation    :4005        │
│  ssdid-registry    :4000        │
│  postgres          :5432        │
│                                 │
│  Nginx (TLS termination) :443   │
└─────────────────────────────────┘
```

#### Standard (3+ Servers)

CA engine isolated on dedicated server. Recommended for government/enterprise.

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   CA Server       │  │   App Server      │  │  Validation      │
│   (secured, HSM)  │  │                   │  │  (DMZ)           │
│                   │  │                   │  │                  │
│  pki-ca-engine    │  │  pki-ca-portal    │  │  pki-validation  │
│                   │  │  pki-ra-portal    │  │  pki-validation  │
│                   │  │  pki-ra-engine    │  │  (N instances)   │
│                   │  │  ssdid-registry   │  │                  │
└───────┬──────────┘  └───────┬──────────┘  └───────┬──────────┘
        │                     │                      │
        └─────────┬───────────┘                      │
                  │                                  │
         ┌───────┴──────────┐               ┌───────┴──────┐
         │  PostgreSQL HA    │               │  PostgreSQL   │
         │  (primary+replica)│               │  (read replica)│
         └──────────────────┘               └──────────────┘
```

#### High Security (Full Isolation)

Every service on dedicated hardware with network segmentation.

```
CA Zone          Portal Zone       RA Zone          DMZ              Audit Zone
─────────────    ──────────────    ─────────────    ─────────────    ─────────────
pki-ca-engine    pki-ca-portal     pki-ra-engine    pki-validation   Audit DB
CA Postgres      pki-ra-portal     RA Postgres      (OCSP/CRL)       SSDID Registry
HSM cluster                                         LDAP
```

### Building Container Images

Each service has a `Containerfile` in its directory. Build from the project root:

```bash
# Build all images
podman build -t pki-ca-engine:latest   -f src/pki_ca_engine/Containerfile .
podman build -t pki-ra-engine:latest   -f src/pki_ra_engine/Containerfile .
podman build -t pki-ca-portal:latest   -f src/pki_ca_portal/Containerfile .
podman build -t pki-ra-portal:latest   -f src/pki_ra_portal/Containerfile .
podman build -t pki-validation:latest  -f src/pki_validation/Containerfile .
```

SSDID Registry is built from the SSDID project:

```bash
podman build -t ssdid-registry:latest -f ../SSDID/src/ssdid_registry/Containerfile ../SSDID
```

### Environment Variables

#### All Services

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY_BASE` | Yes (prod) | — | 64+ byte secret for session signing |
| `RELEASE_DISTRIBUTION` | No | `name` | Erlang distribution mode |
| `RELEASE_NODE` | No | `<app>@<hostname>` | Erlang node name |

#### Database Services (CA Engine, RA Engine, Validation)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes (prod) | — | PostgreSQL connection URL |
| `POOL_SIZE` | No | `10` | Database connection pool size |

#### Web Services (Portals)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `4000` | HTTP listen port |
| `PHX_HOST` | Yes (prod) | — | Public hostname for URL generation |

#### SSDID Integration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSDID_REGISTRY_URL` | No | `http://localhost:4000` | SSDID Registry URL |
| `SSDID_IDENTITY_PASSWORD` | No | `dev_pass` | Password for node DID identity |

#### SSDID Registry

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MNESIA_DIR` | No | `/app/data/mnesia` | Mnesia data directory |
| `DNS_CLUSTER_QUERY` | No | — | DNS query for node discovery |

### Generate Secrets

```bash
# Generate SECRET_KEY_BASE
mix phx.gen.secret
# or
openssl rand -base64 64
```

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

# Audit database
podman run -d --name pki-audit-db \
  -e POSTGRES_USER=pki_audit \
  -e POSTGRES_PASSWORD=<strong-password> \
  -e POSTGRES_DB=pki_audit_trail \
  -v pki-audit-data:/var/lib/postgresql/data \
  -p 5435:5432 \
  docker.io/library/postgres:16-alpine
```

#### Run Migrations

```bash
# For each service with a database:
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiCaEngine.Release.migrate()"
podman exec pki-ra-engine bin/pki_ra_engine eval "PkiRaEngine.Release.migrate()"
podman exec pki-validation bin/pki_validation eval "PkiValidation.Release.migrate()"
```

### Running in Production

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
SSDID_REGISTRY_URL=http://localhost:4000
SSDID_IDENTITY_PASSWORD=<identity-password>
RELEASE_DISTRIBUTION=name
RELEASE_NODE=pki_ca_engine@ca.pki.internal
```

#### Podman Rootless (Recommended for VPS)

```bash
podman run -d \
  --name pki-ca-engine \
  --restart=always \
  -p 127.0.0.1:4001:4001 \
  --env-file /etc/pki/ca-engine.env \
  --memory=1g \
  --cpus=2 \
  pki-ca-engine:latest
```

---

## Operations

### Health Checks

```bash
# All services
for port in 4000 4003 4005; do
  echo -n "Port $port: "
  curl -s http://localhost:$port/health | jq -r .status
done

# Portal check (returns HTML)
curl -s -o /dev/null -w "%{http_code}" http://localhost:4002/login
curl -s -o /dev/null -w "%{http_code}" http://localhost:4004/login
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

### Audit Trail Verification

```bash
# Connect to audit database and verify chain integrity
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiAuditTrail.verify_chain() |> IO.inspect()"
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

### All Services

```bash
# From project root — run all 531 tests
for dir in pki_audit_trail pki_ca_engine pki_ra_engine pki_ca_portal pki_ra_portal pki_validation; do
  echo "=== $dir ==="
  (cd src/$dir && mix test)
done
```

### Individual Service

```bash
cd src/pki_ca_engine
mix test                                    # all tests
mix test test/pki_ca_engine/integration_test.exs  # integration only
mix test --only async:false                 # sync tests only
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
# Verify Postgres is running
podman exec pki-postgres pg_isready -U postgres

# Check databases exist
podman exec pki-postgres psql -U postgres -l
```

### Port Conflicts

```bash
# Check what's using a port
lsof -i :4001

# Use different ports in compose
PORT=4011 podman-compose up pki-ca-engine
```

### Container Build Failures

```bash
# Build with verbose output
podman build --no-cache -t pki-ca-engine:latest -f src/pki_ca_engine/Containerfile . 2>&1 | tee build.log

# Check Elixir/OTP version compatibility
podman run --rm docker.io/hexpm/elixir:1.18.4-erlang-27.3.4.6-debian-trixie-20260223 elixir --version
```

### Mnesia Issues (SSDID Registry)

```bash
# Reset Mnesia data
podman volume rm ssdid-registry-data
podman-compose up -d ssdid-registry
```

---

## Service Ports Summary

| Port | Service | Protocol | Access |
|------|---------|----------|--------|
| 4000 | SSDID Registry | HTTP/JSON | Internal |
| 4001 | CA Engine | Erlang RPC | Internal only |
| 4002 | CA Portal | HTTP (LiveView) | Admin users via Nginx |
| 4003 | RA Engine | HTTP/JSON (REST API) | External clients + Admin via Nginx |
| 4004 | RA Portal | HTTP (LiveView) | Admin users via Nginx |
| 4005 | Validation | HTTP/JSON (OCSP/CRL) | Public via Nginx |
| 5432 | PostgreSQL | PostgreSQL | Internal only |

---

## Security Checklist (Production)

- [ ] Generate unique `SECRET_KEY_BASE` for each service
- [ ] Use separate PostgreSQL instances (or at minimum separate users) per database
- [ ] Enable TLS on all external-facing endpoints (Nginx or direct)
- [ ] Restrict CA Engine port (4001) to internal network only
- [ ] Restrict PostgreSQL port (5432) to internal network only
- [ ] Configure firewall rules (UFW/iptables) per deployment topology
- [ ] Set session cookie `secure: true` (already configured in code)
- [ ] Configure `SSDID_IDENTITY_PASSWORD` with strong unique passwords per service
- [ ] Enable Erlang Distribution TLS (`inet_tls_dist`) for inter-node communication
- [ ] Sign container images with `cosign` before deployment
- [ ] Set up automated database backups
- [ ] Configure audit trail chain verification as a periodic health check
- [ ] Review and restrict Podman container resource limits (memory, CPU)
