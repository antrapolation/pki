# PQC Certificate Authority System — Deployment Guide

## Target Environment

| Component | Specification |
|-----------|--------------|
| **VPS** | Contabo Cloud VPS M+ (6-8 vCPU, 16-30 GB RAM, 200 GB NVMe) |
| **OS** | Ubuntu 24.04 LTS |
| **Runtime** | Podman (rootless containers) |
| **Reverse Proxy** | Caddy (automatic HTTPS via Let's Encrypt) |
| **Database** | PostgreSQL 16 (containerized) |
| **HSM** | SoftHSM2 (containerized, for beta testing) |

---

## 1. VPS Initial Setup

### 1.1 SSH into your VPS

```bash
ssh root@your-vps-ip
```

### 1.2 Create a non-root user

```bash
adduser pki
usermod -aG sudo pki
su - pki
```

### 1.3 Update system

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw
```

### 1.4 Configure firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp    # HTTP (Caddy redirect)
sudo ufw allow 443/tcp   # HTTPS (Caddy)
sudo ufw enable
```

Only ports 22, 80, and 443 are exposed. All PKI services (4001-4005) are internal only.

### 1.5 Install Podman

```bash
sudo apt install -y podman podman-compose
podman --version   # should be 4.x+
```

If `podman-compose` is not available via apt:

```bash
pip3 install podman-compose
```

### 1.6 Install Caddy

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

---

## 2. Deploy the PKI System

### 2.1 Clone the repository

```bash
cd /home/pki
git clone <repo-url> pki
cd pki
```

### 2.2 Configure environment

```bash
cp .env.example .env
```

Edit `.env` with strong production values:

```bash
# Generate secrets
openssl rand -base64 32   # for POSTGRES_PASSWORD
openssl rand -base64 64   # for SECRET_KEY_BASE
openssl rand -base64 32   # for INTERNAL_API_SECRET
openssl rand -hex 4       # for SOFTHSM_SO_PIN (8 hex chars)
openssl rand -hex 4       # for SOFTHSM_USER_PIN
```

```ini
# .env (production values)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=<generated-strong-password>

SOFTHSM_TOKEN_LABEL=PkiCA
SOFTHSM_SO_PIN=<generated-so-pin>
SOFTHSM_USER_PIN=<generated-user-pin>

SECRET_KEY_BASE=<generated-64-byte-secret>
INTERNAL_API_SECRET=<generated-32-byte-secret>
```

### 2.3 Build container images

```bash
podman-compose build
```

This builds 7 images. First build takes 10-15 minutes.

### 2.4 Start all services

```bash
podman-compose up -d
```

Verify all containers are running:

```bash
podman-compose ps
```

Expected: 7 containers, all with "Up" status.

| Service | Container | Internal Port | Description |
|---------|-----------|--------------|-------------|
| PostgreSQL | pki-postgres | 5432 | Shared database |
| SoftHSM2 | pki-softhsm2 | — | PKCS#11 HSM simulator |
| CA Engine | pki-ca-engine | 4001 | Core CA — signing, ceremonies |
| CA Portal | pki-ca-portal | 4002 | CA Admin GUI (Phoenix LiveView) |
| RA Engine | pki-ra-engine | 4003 | Registration Authority — REST API |
| RA Portal | pki-ra-portal | 4004 | RA Admin GUI (Phoenix LiveView) |
| Validation | pki-validation | 4005 | OCSP responder + CRL publisher |

### 2.5 Run database migrations

```bash
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiCaEngine.Release.migrate()"
podman exec pki-ra-engine bin/pki_ra_engine eval "PkiRaEngine.Release.migrate()"
podman exec pki-validation bin/pki_validation eval "PkiValidation.Release.migrate()"
```

### 2.6 Verify health

```bash
# All engines + validation
curl -s http://localhost:4001/health   # {"status":"ok"}
curl -s http://localhost:4003/health   # {"status":"ok"}
curl -s http://localhost:4005/health   # {"status":"ok"}

# Portals
curl -s -o /dev/null -w "%{http_code}" http://localhost:4002/login   # 200
curl -s -o /dev/null -w "%{http_code}" http://localhost:4004/login   # 200
```

---

## 3. Configure Caddy (HTTPS Reverse Proxy)

### 3.1 DNS Setup

Point these domains to your VPS IP in your DNS provider:

| Domain | Points To | Service |
|--------|-----------|---------|
| `ca.yourdomain.com` | VPS IP | CA Portal |
| `ra.yourdomain.com` | VPS IP | RA Portal |
| `api.yourdomain.com` | VPS IP | RA Engine API |
| `ocsp.yourdomain.com` | VPS IP | Validation (OCSP/CRL) |

### 3.2 Configure Caddyfile

```bash
sudo nano /etc/caddy/Caddyfile
```

```
# CA Admin Portal
ca.yourdomain.com {
    reverse_proxy localhost:4002
}

# RA Admin Portal
ra.yourdomain.com {
    reverse_proxy localhost:4004
}

# RA Engine REST API (for external CSR submission)
api.yourdomain.com {
    reverse_proxy localhost:4003
}

# OCSP Responder + CRL Publisher
ocsp.yourdomain.com {
    reverse_proxy localhost:4005
}
```

### 3.3 Start Caddy

```bash
sudo systemctl restart caddy
sudo systemctl enable caddy
```

Caddy automatically obtains Let's Encrypt certificates. Verify:

```bash
curl -s https://ca.yourdomain.com/login -o /dev/null -w "%{http_code}"   # 200
curl -s https://ocsp.yourdomain.com/health                               # {"status":"ok"}
```

---

## 4. Bootstrap Admin Accounts

### 4.1 CA Portal — First Admin

1. Navigate to `https://ca.yourdomain.com/setup`
2. Enter **Username** (min 3 characters)
3. Enter **Display Name** (optional)
4. Enter **Password** (min 8 characters)
5. Confirm password
6. Click **Create Admin Account**
7. You will be redirected to the login page

This page is only accessible when no users exist. After the first admin is created, `/setup` redirects to `/login`.

### 4.2 RA Portal — First Admin

Same process at `https://ra.yourdomain.com/setup`.

### 4.3 Login

Navigate to `/login` and sign in with the credentials created during setup.

---

## 5. Service-to-Service Communication

The PKI services communicate internally:

```
┌─────────────┐     HTTP/JSON      ┌─────────────┐
│  CA Portal   │ ──────────────────→│  CA Engine   │
│  :4002       │  Bearer auth       │  :4001       │
└─────────────┘                     └──────┬───────┘
                                           │ notify
┌─────────────┐     HTTP/JSON      ┌──────▼───────┐
│  RA Portal   │ ──────────────────→│  RA Engine   │
│  :4004       │  Bearer auth       │  :4003       │
└─────────────┘                     └──────┬───────┘
                                           │ sign CSR
                                    ┌──────▼───────┐
                                    │  CA Engine   │
                                    │  :4001       │
                                    └──────┬───────┘
                                           │ notify
                                    ┌──────▼───────┐
                                    │  Validation  │
                                    │  :4005       │
                                    └──────────────┘
```

All service-to-service calls use `INTERNAL_API_SECRET` for Bearer token authentication. This is configured automatically via the `.env` file and `compose.yml`.

---

## 6. Environment Variables Reference

### Shared (all services)

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY_BASE` | Yes | 64+ byte secret for session signing |
| `INTERNAL_API_SECRET` | Yes | Shared secret for service-to-service auth |

### Database services (CA Engine, RA Engine, Validation)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | `ecto://USER:PASS@HOST:PORT/DB` |
| `PORT` | No | `4001/4003/4005` | HTTP listen port |
| `VALIDATION_URL` | CA Engine only | — | URL of validation service |

### Portal services (CA Portal, RA Portal)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `4002/4004` | HTTP listen port |
| `PHX_HOST` | Yes | — | Public hostname (e.g., `ca.yourdomain.com`) |
| `PHX_SERVER` | Yes | — | Set to `true` |
| `CA_ENGINE_URL` / `RA_ENGINE_URL` | Yes | — | Engine API base URL |
| `ENGINE_CLIENT_MODE` | No | — | Set to `mock` for testing with mock data |

### HSM (CA Engine)

| Variable | Default | Description |
|----------|---------|-------------|
| `PKCS11_LIB_PATH` | `/hsm/lib/libsofthsm2.so` | Path to PKCS#11 library |
| `HSM_SLOT` | `0` | HSM slot ID |
| `HSM_PIN` | from `.env` | User PIN |
| `HSM_TOKEN_LABEL` | `PkiCA` | Token label |

---

## 7. Operations

### Health checks

```bash
# Quick check all services
for port in 4001 4003 4005; do
  echo "Port $port: $(curl -s http://localhost:$port/health)"
done

for port in 4002 4004; do
  echo "Port $port: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:$port/login)"
done
```

### View logs

```bash
# All services
podman-compose logs -f

# Specific service
podman logs pki-ca-engine --follow
podman logs pki-ra-engine --follow --tail 100
```

### Database backup

```bash
#!/bin/bash
# /home/pki/backup.sh
DATE=$(date +%Y%m%d_%H%M)
BACKUP_DIR=/home/pki/backups/$DATE
mkdir -p $BACKUP_DIR

for db in pki_ca_engine pki_ra_engine pki_validation pki_audit_trail; do
  podman exec pki-postgres pg_dump -U postgres $db | gzip > $BACKUP_DIR/${db}.sql.gz
done

echo "Backup complete: $BACKUP_DIR"

# Rotate: keep last 30 days
find /home/pki/backups -maxdepth 1 -mtime +30 -exec rm -rf {} \;
```

Set up daily cron:

```bash
crontab -e
# Add:
0 2 * * * /home/pki/backup.sh >> /home/pki/backups/cron.log 2>&1
```

### Database restore

```bash
gunzip < backup_pki_ca_engine.sql.gz | podman exec -i pki-postgres psql -U postgres pki_ca_engine
```

### Restart services

```bash
# Restart a single service
podman-compose restart pki-ca-engine

# Restart all
podman-compose restart

# Full stop and start (recreates containers)
podman-compose down
podman-compose up -d
```

### Update (deploy new version)

```bash
cd /home/pki/pki
git pull
podman-compose build
podman-compose down
podman-compose up -d

# Run any new migrations
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiCaEngine.Release.migrate()"
podman exec pki-ra-engine bin/pki_ra_engine eval "PkiRaEngine.Release.migrate()"
podman exec pki-validation bin/pki_validation eval "PkiValidation.Release.migrate()"
```

---

## 8. HSM Configuration

### SoftHSM2 (Beta Testing)

SoftHSM2 runs as a container and shares its library + token storage with the CA Engine via volumes. This is the default configuration for beta testing.

```
pki-softhsm2 → softhsm-lib volume → pki-ca-engine:/hsm/lib/ (ro)
              → softhsm-tokens volume → pki-ca-engine:/hsm/tokens/ (ro)
```

### Verify HSM

```bash
# Show slots
podman exec pki-softhsm2 softhsm2-util --show-slots

# List objects
podman exec pki-softhsm2 pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label PkiCA --pin $SOFTHSM_USER_PIN --list-objects
```

### Swapping to a Real HSM (Production)

Only change environment variables on `pki-ca-engine`:

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

Remove the `softhsm2` service and its volumes from compose.yml. Mount the vendor's PKCS#11 library from the host.

---

## 9. Running Tests

### ExUnit tests (all services)

```bash
# Requires PostgreSQL on localhost:5434
for dir in pki_ca_engine pki_ra_engine pki_ca_portal pki_ra_portal pki_validation; do
  echo "=== $dir ==="
  (cd src/$dir && mix test)
done
```

Expected: ~648 tests, 0 failures.

### Playwright E2E tests

```bash
cd e2e
npm install
npx playwright install chromium

# Start services in mock mode for testing
ENGINE_CLIENT_MODE=mock podman-compose up -d

# Run all 110 tests
npx playwright test

# Run by module
npx playwright test --project=ca-portal
npx playwright test --project=ra-portal
npx playwright test --project=ra-api
npx playwright test --project=validation
npx playwright test --project=e2e
```

---

## 10. Security Checklist

### Before Go-Live

- [ ] Change ALL values in `.env` from defaults
- [ ] Generate unique `SECRET_KEY_BASE` with `openssl rand -base64 64`
- [ ] Generate unique `INTERNAL_API_SECRET` with `openssl rand -base64 32`
- [ ] Set strong PostgreSQL password
- [ ] Set strong HSM PINs
- [ ] DNS records configured for all subdomains
- [ ] Caddy running with valid SSL certificates
- [ ] Firewall configured (only 22, 80, 443 open)
- [ ] All health endpoints returning `{"status":"ok"}`
- [ ] Database migrations run successfully
- [ ] Admin accounts created via `/setup`
- [ ] Login works on both portals

### Ongoing

- [ ] Daily database backups via cron
- [ ] Monitor container health: `podman-compose ps`
- [ ] Review audit logs periodically via CA Portal
- [ ] Rotate `INTERNAL_API_SECRET` periodically
- [ ] Keep OS and Podman updated
- [ ] Monitor disk usage (PostgreSQL data, container images)

---

## 11. Troubleshooting

### Container won't start

```bash
# Check logs
podman logs pki-ca-engine

# Common: missing env var
# Fix: ensure .env has all required values
```

### "needs_setup" even after creating admin

```bash
# Check if migrations ran
podman exec pki-ca-engine bin/pki_ca_engine eval "PkiCaEngine.Release.migrate()"
```

### Database connection refused

```bash
# Verify postgres is healthy
podman exec pki-postgres pg_isready -U postgres

# Check DATABASE_URL
podman exec pki-ca-engine printenv DATABASE_URL
```

### Portal shows unstyled HTML

The LiveView JavaScript didn't load. Rebuild the portal with no cache:

```bash
podman-compose build --no-cache pki-ca-portal pki-ra-portal
podman-compose up -d pki-ca-portal pki-ra-portal
```

### WebSocket connection failed

Caddy must proxy WebSocket connections. The default `reverse_proxy` directive handles this. If using Nginx instead, add:

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

### Service-to-service 401 errors

Check that `INTERNAL_API_SECRET` is the same value across all services in `.env`.

---

## 12. Architecture Diagram

```
                         Internet
                            │
                        ┌───▼───┐
                        │ Caddy │  (HTTPS, auto Let's Encrypt)
                        │  :443 │
                        └───┬───┘
            ┌───────────────┼───────────────┬──────────────┐
            │               │               │              │
      ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐  ┌────▼──────┐
      │ CA Portal │  │ RA Portal │  │ RA Engine │  │Validation │
      │   :4002   │  │   :4004   │  │   :4003   │  │   :4005   │
      └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └───────────┘
            │               │               │              ▲
            │   HTTP/JSON   │   HTTP/JSON   │  sign CSR    │ notify
            └──────┐        └──────┐        └──────┐       │
                   ▼               ▼               ▼       │
              ┌────────────────────────────────────────────┐
              │              CA Engine :4001                │
              │   Key Ceremony │ Certificate Signing        │
              │   Threshold Shares │ Key Activation         │
              └────────────┬───────────────────────────────┘
                           │
                    ┌──────▼──────┐     ┌──────────────┐
                    │ PostgreSQL  │     │  SoftHSM2    │
                    │   :5432     │     │  (PKCS#11)   │
                    │ 4 databases │     │  Key Storage  │
                    └─────────────┘     └──────────────┘
```

---

## 13. Service Ports (Internal Only)

| Port | Service | Protocol | External Access |
|------|---------|----------|----------------|
| 4001 | CA Engine | HTTP/JSON | **No** — internal only |
| 4002 | CA Portal | HTTP (LiveView) | Via Caddy (`ca.yourdomain.com`) |
| 4003 | RA Engine | HTTP/JSON (REST) | Via Caddy (`api.yourdomain.com`) |
| 4004 | RA Portal | HTTP (LiveView) | Via Caddy (`ra.yourdomain.com`) |
| 4005 | Validation | HTTP/JSON (OCSP/CRL) | Via Caddy (`ocsp.yourdomain.com`) |
| 5432 | PostgreSQL | PostgreSQL | **No** — internal only |
