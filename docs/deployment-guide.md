# PQC Certificate Authority System — Deployment Guide

## Target Environment

| Component | Specification |
|-----------|--------------|
| **VPS Provider** | Contabo Cloud VPS (8 vCPU, 24 GB RAM, 500 GB NVMe) |
| **OS** | Ubuntu 24.04 LTS |
| **Runtime** | Podman (rootless containers) |
| **Reverse Proxy** | Caddy (automatic HTTPS via Let's Encrypt) |
| **Database** | PostgreSQL 17 (containerized, multi-tenant) |
| **HSM** | SoftHSM2 (containerized, for beta testing) |

---

## 1. VPS Initial Setup (Contabo)

### 1.1 Order VPS

1. Go to [contabo.com](https://contabo.com) → Cloud VPS
2. Select **Cloud VPS** (8 vCPU, 24 GB RAM, 500 GB NVMe)
3. Choose **Ubuntu 24.04** as OS
4. Choose region closest to your testers (EU-DE or Asia-SG)
5. Complete order — you'll receive root credentials via email

### 1.2 SSH into your VPS

```bash
ssh root@your-vps-ip
```

### 1.3 Create a non-root user

```bash
adduser pki
usermod -aG sudo pki
su - pki
```

### 1.4 Set up SSH key authentication

**Do this BEFORE disabling password login, or you will lock yourself out.**

#### Step 1: Generate an SSH key (on your local machine)

Skip this if you already have a key at `~/.ssh/id_ed25519.pub`.

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

When prompted:
- **File location** — press Enter to accept the default (`~/.ssh/id_ed25519`)
- **Passphrase** — enter a strong passphrase (recommended) or press Enter for none

This creates two files:
- `~/.ssh/id_ed25519` — your **private key** (never share this)
- `~/.ssh/id_ed25519.pub` — your **public key** (this goes on the server)

#### Step 2: Copy the public key to the VPS

```bash
ssh-copy-id pki@your-vps-ip
```

You'll be prompted for the `pki` user's password one last time. After this, your key is added to `~/.ssh/authorized_keys` on the VPS.

If `ssh-copy-id` is not available (e.g., on Windows), do it manually:

```bash
# Show your public key
cat ~/.ssh/id_ed25519.pub

# SSH into VPS as root, then set up the pki user's key
ssh root@your-vps-ip
su - pki
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "paste-your-public-key-here" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
exit
exit
```

#### Step 3: Test key-based login

```bash
ssh pki@your-vps-ip
```

If this connects **without asking for a password** (or only asks for your key passphrase), it's working.

#### Adding teammates

Each person generates their own key on their machine and sends you the `.pub` file. On the VPS:

```bash
echo "ssh-ed25519 AAAA...their-key... teammate@email.com" >> ~/.ssh/authorized_keys
```

To revoke access, remove their line from `~/.ssh/authorized_keys`.

### 1.5 Secure SSH (recommended)

Only do this AFTER confirming `ssh pki@your-vps-ip` works with your key:

```bash
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
# Set: PasswordAuthentication no
sudo systemctl restart ssh
```

### 1.6 Update system

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw
```

### 1.7 Configure firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp    # HTTP (Caddy redirect)
sudo ufw allow 443/tcp   # HTTPS (Caddy)
sudo ufw enable
```

Only ports 22, 80, and 443 are exposed. All PKI services (4001-4006) are internal only.

### 1.8 Install Podman

```bash
sudo apt install -y podman podman-compose
podman --version   # should be 4.x+
```

If `podman-compose` is not available via apt:

```bash
sudo apt install -y pipx
pipx install podman-compose
pipx ensurepath
source ~/.bashrc
```

### 1.9 Install Caddy

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
git clone https://vcs.antrapol.tech:3800/Incubator/pki.git
cd pki
git checkout v1.0.0-beta.2
```

### 2.2 Configure environment

```bash
cp .env.example .env
nano .env
```

Generate strong production values:

```bash
openssl rand -base64 32   # for POSTGRES_PASSWORD
openssl rand -base64 64   # for SECRET_KEY_BASE
openssl rand -base64 32   # for INTERNAL_API_SECRET
openssl rand -hex 4       # for SOFTHSM_SO_PIN
openssl rand -hex 4       # for SOFTHSM_USER_PIN
```

```ini
# .env (production values — change ALL of these)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=<generated-strong-password>

SOFTHSM_TOKEN_LABEL=PkiCA
SOFTHSM_SO_PIN=<generated-8-hex-chars>
SOFTHSM_USER_PIN=<generated-8-hex-chars>

SECRET_KEY_BASE=<generated-64-byte-secret>
INTERNAL_API_SECRET=<generated-32-byte-secret>

# Platform admin (for tenant management portal)
PLATFORM_ADMIN_USERNAME=<chosen-username>
PLATFORM_ADMIN_PASSWORD=<strong-password>
```

### 2.3 Build container images

```bash
podman-compose build
```

First build takes 15-25 minutes (compiles Elixir, downloads Erlang, builds assets).

### 2.4 Start all services

```bash
podman-compose up -d
```

Verify all containers are running:

```bash
podman-compose ps
```

Expected: 8 containers, all with "Up" status.

| Service | Container | Internal Port | Description |
|---------|-----------|--------------|-------------|
| PostgreSQL | pki-postgres | 5432 | Multi-tenant database server |
| SoftHSM2 | pki-softhsm2 | — | PKCS#11 HSM simulator |
| CA Engine | pki-ca-engine | 4001 | Core CA — signing, ceremonies, credentials |
| CA Portal | pki-ca-portal | 4002 | CA Admin GUI (Phoenix LiveView) |
| RA Engine | pki-ra-engine | 4003 | Registration Authority — REST API |
| RA Portal | pki-ra-portal | 4004 | RA Admin GUI (Phoenix LiveView) |
| Validation | pki-validation | 4005 | OCSP responder + CRL publisher |
| Platform Portal | pki-platform-portal | 4006 | Tenant management GUI |

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
curl -s -o /dev/null -w "%{http_code}" http://localhost:4006/login   # 200
```

---

## 3. Configure Caddy (HTTPS Reverse Proxy)

### 3.1 DNS Setup

Point these domains to your VPS IP in your DNS provider:

| Domain | Points To | Service |
|--------|-----------|---------|
| `straptrust.com` | VPS IP | Marketing landing page |
| `ca.straptrust.com` | VPS IP | CA Portal |
| `ra.straptrust.com` | VPS IP | RA Portal |
| `api.straptrust.com` | VPS IP | RA Engine API |
| `ocsp.straptrust.com` | VPS IP | Validation (OCSP/CRL) |
| `admin.straptrust.com` | VPS IP | Platform Portal |

### 3.2 Configure Caddyfile

```bash
sudo nano /etc/caddy/Caddyfile
```

```
# Marketing Landing Page (static HTML)
straptrust.com {
    root * /home/pki/pki/landing
    file_server
}

# CA Admin Portal
ca.straptrust.com {
    reverse_proxy localhost:4002
}

# RA Admin Portal
ra.straptrust.com {
    reverse_proxy localhost:4004
}

# RA Engine REST API (for external CSR submission)
api.straptrust.com {
    reverse_proxy localhost:4003
}

# OCSP Responder + CRL Publisher
ocsp.straptrust.com {
    reverse_proxy localhost:4005
}

# Platform Admin Portal (tenant management)
admin.straptrust.com {
    reverse_proxy localhost:4006
}
```

### 3.3 Start Caddy

```bash
sudo systemctl restart caddy
sudo systemctl enable caddy
```

Caddy automatically obtains Let's Encrypt certificates. Verify:

```bash
curl -s https://straptrust.com -o /dev/null -w "%{http_code}"               # 200 (landing page)
curl -s https://ca.straptrust.com/login -o /dev/null -w "%{http_code}"     # 200
curl -s https://ocsp.straptrust.com/health                                  # {"status":"ok"}
curl -s https://admin.straptrust.com/login -o /dev/null -w "%{http_code}"   # 200
```

---

## 4. Initial Setup Flow

### 4.1 Platform Admin Login (Tenant Management)

1. Navigate to `https://admin.straptrust.com/login`
2. Enter the `PLATFORM_ADMIN_USERNAME` and `PLATFORM_ADMIN_PASSWORD` from `.env`
3. Dashboard shows: tenant count, active tenants

### 4.2 Create a Tenant

1. In the Platform Portal, click **Create Tenant**
2. Enter **Organization Name** and **Subdomain Slug**
3. System provisions a dedicated database with 4 schemas (ca/ra/validation/audit)
4. Tenant status becomes "initialized"

### 4.3 CA Portal — Bootstrap First Admin

1. Navigate to `https://ca.straptrust.com/setup`
2. Enter **Username** (min 3 characters)
3. Enter **Display Name** (optional)
4. Enter **Password** (min 8 characters)
5. Confirm password
6. Click **Initialize Certificate Authority**
7. System creates:
   - CA Admin user with dual keypairs (signing + KEM)
   - Keypair ACL credential (cryptographic access control)
   - 4 system keypairs (root, sub_root, service host signing, service host cipher)
8. Redirected to login page

### 4.4 RA Portal — Bootstrap First Admin

1. Navigate to `https://ra.straptrust.com/setup`
2. Same process — creates RA Admin with dual keypairs
3. Redirected to login page

### 4.5 Login

Navigate to `/login` and sign in. The system verifies:
1. Password hash (Argon2)
2. Signing key ownership (decrypt test)
3. Attestation certificate validity (public key signed by creating admin)
4. Returns a session key for crypto operations

---

## 5. Service Architecture

```
                         Internet
                            │
                        ┌───▼───┐
                        │ Caddy │  HTTPS + Auto Let's Encrypt
                        └───┬───┘
         ┌──────────────────┼──────────────────┬───────────────┐
         │                  │                  │               │
   ┌─────▼──────┐    ┌─────▼──────┐    ┌─────▼──────┐  ┌────▼───────┐
   │  Platform   │    │ CA Portal  │    │ RA Portal  │  │ Validation │
   │   Portal    │    │   :4002    │    │   :4004    │  │   :4005    │
   │   :4006     │    └─────┬──────┘    └─────┬──────┘  └────────────┘
   └─────┬───────┘          │                 │               ▲
         │            ┌─────▼──────┐    ┌─────▼──────┐        │
         │            │ CA Engine  │    │ RA Engine  │────────┘
         │            │   :4001    │◄───│   :4003    │  notify
         │            │            │    └────────────┘
         │            │ Modules:   │
         │            │ Credential Manager
         │            │ Key Ceremony Manager
         │            │ Key Vault + Keypair ACL
         │            │ Certificate Signing
         │            └─────┬──────┘
         │                  │
   ┌─────▼──────────────────▼─────────────────────────────────┐
   │                   PostgreSQL 17                           │
   │                                                           │
   │  pki_platform    pki_tenant_{uuid}    pki_tenant_{uuid}   │
   │  (shared)        ├── ca.*             ├── ca.*            │
   │                  ├── ra.*             ├── ra.*            │
   │                  ├── validation.*     ├── validation.*    │
   │                  └── audit.*          └── audit.*         │
   └──────────────────────────────────────────────────────────┘
```

### Multi-Tenant Database Model

Each tenant gets its own PostgreSQL database (`pki_tenant_{uuid}`) with 4 schemas:
- `ca` — CA users, credentials, keypairs, keystores, ceremonies, certificates
- `ra` — RA users, CSR requests, cert profiles, API keys, service configs
- `validation` — certificate status (OCSP/CRL)
- `audit` — audit trail events

Schema-level role isolation ensures CA code cannot access RA tables and vice versa.

### Service-to-Service Communication

All internal API calls use `INTERNAL_API_SECRET` for Bearer token authentication. This is configured automatically via `.env` and `compose.yml`.

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
| `PHX_HOST` | Yes | — | Public hostname (e.g., `ca.straptrust.com`) |
| `PHX_SERVER` | Yes | — | Set to `true` |
| `CA_ENGINE_URL` / `RA_ENGINE_URL` | Yes | — | Engine API base URL |

### Platform Portal

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Default: 4006 |
| `DATABASE_URL` | Yes | URL to pki_platform database |
| `PLATFORM_ADMIN_USERNAME` | Yes (prod) | Platform superadmin username |
| `PLATFORM_ADMIN_PASSWORD` | Yes (prod) | Platform superadmin password |

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

for port in 4002 4004 4006; do
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

# Backup platform database
podman exec pki-postgres pg_dump -U postgres pki_platform | gzip > $BACKUP_DIR/pki_platform.sql.gz

# Backup all tenant databases
for db in $(podman exec pki-postgres psql -U postgres -t -c "SELECT datname FROM pg_database WHERE datname LIKE 'pki_tenant_%'"); do
  db=$(echo $db | xargs)  # trim whitespace
  podman exec pki-postgres pg_dump -U postgres $db | gzip > $BACKUP_DIR/${db}.sql.gz
done

# Backup legacy databases (if they exist from beta.1)
for db in pki_ca_engine pki_ra_engine pki_validation pki_audit_trail; do
  podman exec pki-postgres pg_dump -U postgres $db 2>/dev/null | gzip > $BACKUP_DIR/${db}.sql.gz
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
gunzip < backup_pki_platform.sql.gz | podman exec -i pki-postgres psql -U postgres pki_platform
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

SoftHSM2 runs as a container and shares its library + token storage with the CA Engine via volumes.

```
pki-softhsm2 → softhsm-lib volume → pki-ca-engine:/hsm/lib/ (ro)
              → softhsm-tokens volume → pki-ca-engine:/hsm/tokens/ (ro)
```

### Verify HSM

```bash
podman exec pki-softhsm2 softhsm2-util --show-slots

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
for dir in pki_crypto pki_platform_engine pki_ca_engine pki_ra_engine pki_ca_portal pki_ra_portal pki_validation pki_platform_portal; do
  echo "=== $dir ==="
  (cd src/$dir && mix test)
done
```

Expected: ~975 tests, 0 failures.

### Playwright E2E tests

```bash
cd e2e
npm install
npx playwright install chromium

# Start services in mock mode for portal UI testing
ENGINE_CLIENT_MODE=mock podman-compose up -d

# Run all 139 tests
npx playwright test

# Run by project
npx playwright test --project=ca-portal    # CA Portal UI
npx playwright test --project=ra-portal    # RA Portal UI
npx playwright test --project=ca-api       # CA Engine API
npx playwright test --project=ra-api       # RA Engine API
npx playwright test --project=validation   # OCSP/CRL
npx playwright test --project=e2e          # Cross-module flows
```

---

## 10. Security Checklist

### Before Go-Live

- [ ] Change ALL values in `.env` from defaults
- [ ] Generate unique `SECRET_KEY_BASE` with `openssl rand -base64 64`
- [ ] Generate unique `INTERNAL_API_SECRET` with `openssl rand -base64 32`
- [ ] Set strong PostgreSQL password
- [ ] Set strong HSM PINs
- [ ] Set strong `PLATFORM_ADMIN_USERNAME` and `PLATFORM_ADMIN_PASSWORD`
- [ ] DNS records configured for all 5 subdomains
- [ ] Caddy running with valid SSL certificates
- [ ] Firewall configured (only 22, 80, 443 open)
- [ ] All health endpoints returning `{"status":"ok"}`
- [ ] Database migrations run successfully
- [ ] Platform admin can login at `admin.straptrust.com`
- [ ] Tenant created via Platform Portal
- [ ] CA admin bootstrapped via `/setup` (creates credentials + ACL + system keypairs)
- [ ] RA admin bootstrapped via `/setup` (creates credentials)
- [ ] Login works on both portals with credential verification
- [ ] SSH root login disabled

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

Caddy handles WebSocket proxying automatically. If using Nginx instead:

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

### Service-to-service 401 errors

Check that `INTERNAL_API_SECRET` is the same value across all services in `.env`.

### Bootstrap creates no credentials

Ensure the password is at least 8 characters. Check CA Engine logs for keypair generation errors:

```bash
podman logs pki-ca-engine | grep -i "credential\|keypair\|error"
```

---

## 12. Service Ports (Internal Only)

| Port | Service | Protocol | External Access |
|------|---------|----------|----------------|
| 4001 | CA Engine | HTTP/JSON | **No** — internal only |
| 4002 | CA Portal | HTTP (LiveView) | Via Caddy (`ca.straptrust.com`) |
| 4003 | RA Engine | HTTP/JSON (REST) | Via Caddy (`api.straptrust.com`) |
| 4004 | RA Portal | HTTP (LiveView) | Via Caddy (`ra.straptrust.com`) |
| 4005 | Validation | HTTP/JSON (OCSP/CRL) | Via Caddy (`ocsp.straptrust.com`) |
| 4006 | Platform Portal | HTTP (LiveView) | Via Caddy (`admin.straptrust.com`) |
| 5432 | PostgreSQL | PostgreSQL | **No** — internal only |

---

## 13. Contabo-Specific Notes

### Resource Allocation

| Component | CPU | RAM | Disk |
|-----------|-----|-----|------|
| PostgreSQL | 1-2 cores | 4-8 GB | Scales with tenants |
| CA Engine | 1-2 cores | 1-2 GB | Minimal (key ceremony peaks) |
| RA Engine | 1 core | 512 MB | Minimal |
| CA Portal | 1 core | 512 MB | Minimal |
| RA Portal | 1 core | 512 MB | Minimal |
| Platform Portal | 0.5 core | 256 MB | Minimal |
| Validation | 0.5 core | 256 MB | Minimal |
| SoftHSM2 | 0.5 core | 128 MB | Minimal |
| **Total** | ~7 cores | ~10 GB | ~50 GB initial |

VPS L (8 vCPU, 30 GB RAM) provides comfortable headroom for 10-50 concurrent testers.

### Scaling

- **More tenants**: PostgreSQL handles hundreds of databases on one server. Monitor disk and connection count.
- **More users**: Each portal LiveView session uses ~10 MB RAM. 100 concurrent users ≈ 1 GB additional.
- **More certificates**: OCSP cache is in-memory (ETS). CRL regeneration is periodic. Scale validation horizontally if needed.

### Backup to Contabo Object Storage (Optional)

```bash
# Install s3cmd
sudo apt install s3cmd

# Configure with Contabo Object Storage credentials
s3cmd --configure

# Upload backups
s3cmd put /home/pki/backups/$(date +%Y%m%d)/ s3://pki-backups/$(date +%Y%m%d)/ --recursive
```
