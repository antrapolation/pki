# PKI CA System — Production Deployment Guide
## BEAM Direct Deployment (No Containers)

This guide covers deploying all PKI services as native Elixir/OTP releases supervised
by systemd. No Docker/Podman required. Caddy handles TLS termination; PostgreSQL and
SoftHSM2 run as system services.

---

## Architecture Overview

```
Internet
    │
    ▼
┌─────────────────────────────────────────────┐
│  Caddy (ports 80/443)                        │
│  ca.straptrust.com  → localhost:4002         │
│  ra.straptrust.com  → localhost:4004         │
│  admin.straptrust.com → localhost:4006       │
└────────────┬──────────────┬─────────────────┘
             │              │
    ┌────────▼───┐    ┌─────▼──────┐    ┌───────────────────┐
    │ CA Portal  │    │ RA Portal  │    │ Platform Portal   │
    │ :4002      │    │ :4004      │    │ :4006             │
    └────────┬───┘    └─────┬──────┘    └───────────────────┘
             │              │
    ┌────────▼───┐    ┌─────▼──────┐    ┌───────────────────┐
    │ CA Engine  │◄───│ RA Engine  │    │ Validation Svc    │
    │ :4001      │    │ :4003      │    │ :4005             │
    └────────┬───┘    └────────────┘    └───────────────────┘
             │
    ┌────────▼───────────────────────────────────┐
    │ PostgreSQL :5432  │  SoftHSM2              │
    └────────────────────────────────────────────┘

Each box = one BEAM VM supervised by systemd
BEAM scheduler limit: +S 2:2 per VM (prevents CPU contention on small servers)
```

---

## Table of Contents

1. [Server Requirements](#1-server-requirements)
2. [DNS Setup](#2-dns-setup)
3. [Initial Server Setup](#3-initial-server-setup)
4. [Configure Environment](#4-configure-environment)
5. [Database Initialisation](#5-database-initialisation)
6. [SoftHSM2 Token Initialisation](#6-softhsm2-token-initialisation)
7. [Build Releases](#7-build-releases)
8. [Deploy Releases](#8-deploy-releases)
9. [Start All Services](#9-start-all-services)
10. [Verify Deployment](#10-verify-deployment)
11. [Operations Reference](#11-operations-reference)
12. [Upgrading](#12-upgrading)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Server Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB |
| Disk | 20 GB | 40 GB SSD |
| Network | Public IP | Public IP |

All three domains must resolve to this server's public IP before deployment
(Caddy needs to reach Let's Encrypt for TLS certificate issuance).

---

## 2. DNS Setup

Create three A records pointing to your server's public IP:

| Record | Type | Value |
|---|---|---|
| `ca.straptrust.com` | A | `<your server IP>` |
| `ra.straptrust.com` | A | `<your server IP>` |
| `admin.straptrust.com` | A | `<your server IP>` |

Verify propagation before continuing:
```bash
dig +short ca.straptrust.com
dig +short ra.straptrust.com
dig +short admin.straptrust.com
# All three should return your server IP
```

---

## 3. Initial Server Setup

Run once on the fresh server as root. This installs system packages, creates the
`pki` OS user, sets up directory structure, generates Erlang cookies, and installs
systemd service files.

```bash
# Upload the repo to the server first
scp -r /path/to/pki user@your-server:~/pki
ssh user@your-server

# On the server:
cd ~/pki
sudo bash deploy/install.sh
```

What `install.sh` does:
- Installs **Erlang/OTP + Elixir** via Erlang Solutions repository
- Installs **PostgreSQL 14**, **SoftHSM2**, **Caddy**
- Creates OS user `pki` with home at `/opt/pki`
- Creates `/opt/pki/releases/{ca_engine,ra_engine,...}` directories
- Generates a unique Erlang cookie per service in `/opt/pki/.cookies/` (mode 400)
- Writes `/etc/softhsm2.conf` with token directory `/var/lib/softhsm/tokens/`
- Copies `Caddyfile` to `/etc/caddy/Caddyfile`
- Installs all six systemd `.service` files to `/etc/systemd/system/`
- Copies `.env.production` template to `/opt/pki/.env`

---

## 4. Configure Environment

Edit the environment file — **all `CHANGE_ME` values must be replaced**:

```bash
sudo nano /opt/pki/.env
```

### 4.1 Generate secrets

Run these on any machine with OpenSSL installed:

```bash
# SECRET_KEY_BASE (one shared value, all portals use it)
openssl rand -base64 64

# INTERNAL_API_SECRET
openssl rand -base64 32

# POSTGRES_PASSWORD
openssl rand -base64 24

# SoftHSM SO PIN (security officer — used for token admin)
openssl rand -hex 4

# SoftHSM USER PIN (user — used by CA engine for key operations)
openssl rand -hex 4
```

### 4.2 Complete .env reference

```bash
# PostgreSQL
POSTGRES_USER=postgres
POSTGRES_PASSWORD=<generated>

# Shared secrets
SECRET_KEY_BASE=<generated 64-byte base64>
INTERNAL_API_SECRET=<generated 32-byte base64>

# Platform admin credentials
PLATFORM_ADMIN_USERNAME=trust_admin
PLATFORM_ADMIN_PASSWORD=<strong password>
# OR use a pre-hashed value (more secure):
# PLATFORM_ADMIN_PASSWORD_HASH=<argon2 hash — see below>

# Portal hostnames
CA_PORTAL_HOST=ca.straptrust.com
RA_PORTAL_HOST=ra.straptrust.com
PLATFORM_HOST=admin.straptrust.com

# Caddy ACME
CADDY_ACME_EMAIL=amirrudin.yahaya@gmail.com

# Session signing salts (these are the values from your .env — already set)
CA_PORTAL_SIGNING_SALT=S3aUcrxNqpSe6dTCEKCkLw
RA_PORTAL_SIGNING_SALT=zPADPtaz6F6QSMojQsQJjw
PLATFORM_SIGNING_SALT=eQtmTJO55PJHF2bY9QptWg

# SoftHSM2
SOFTHSM_TOKEN_LABEL=PkiCA
SOFTHSM_SO_PIN=<generated 4-byte hex>
SOFTHSM_USER_PIN=<generated 4-byte hex>
PKCS11_LIB_PATH=/usr/lib/softhsm/libsofthsm2.so
HSM_SLOT=0
HSM_TOKEN_LABEL=PkiCA
SOFTHSM2_CONF=/etc/softhsm2.conf

# Internal service URLs (localhost — no containers)
CA_ENGINE_URL=http://127.0.0.1:4001
RA_ENGINE_URL=http://127.0.0.1:4003
VALIDATION_URL=http://127.0.0.1:4005

# Database URLs (PostgreSQL on localhost:5432)
CA_ENGINE_DATABASE_URL=ecto://postgres:<POSTGRES_PASSWORD>@localhost:5432/pki_ca_engine
RA_ENGINE_DATABASE_URL=ecto://postgres:<POSTGRES_PASSWORD>@localhost:5432/pki_ra_engine
VALIDATION_DATABASE_URL=ecto://postgres:<POSTGRES_PASSWORD>@localhost:5432/pki_validation
PLATFORM_DATABASE_URL=ecto://postgres:<POSTGRES_PASSWORD>@localhost:5432/pki_platform
```

### 4.3 (Optional) Pre-hash the admin password

Instead of storing the platform admin password as plaintext in `.env`, generate
an Argon2 hash and use `PLATFORM_ADMIN_PASSWORD_HASH` instead:

```bash
# Install argon2 CLI if needed
sudo apt-get install -y argon2

# Generate hash
echo -n "your_password" | argon2 $(openssl rand -hex 8) -id -t 3 -m 16 -p 4 -l 32

# Or use the mix task after building the platform portal release:
/opt/pki/releases/platform_portal/bin/pki_platform_portal eval \
  'IO.puts Argon2.hash_pwd_salt("your_password")'
```

Then in `.env`:
```bash
# Remove PLATFORM_ADMIN_PASSWORD and use:
PLATFORM_ADMIN_PASSWORD_HASH=$argon2id$v=19$m=65536,...
```

---

## 5. Database Initialisation

Run once to create all PKI databases:

```bash
# As postgres superuser
sudo -u postgres psql << 'SQL'
CREATE DATABASE pki_ca_engine;
CREATE DATABASE pki_ra_engine;
CREATE DATABASE pki_validation;
CREATE DATABASE pki_audit_trail;
CREATE DATABASE pki_platform;
SQL

# Set the postgres user password to match your .env POSTGRES_PASSWORD
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '<your POSTGRES_PASSWORD>';"

echo "Databases created."
sudo -u postgres psql -l
```

---

## 6. SoftHSM2 Token Initialisation

SoftHSM2 replaces a hardware HSM for development and moderate-security production use.
The token must be initialised **before** the CA engine starts for the first time.

```bash
# Verify SoftHSM2 is installed and the pki user can access it
sudo -u pki softhsm2-util --show-slots

# Initialise the PkiCA token
# Use the SO_PIN and USER_PIN values from your .env
source /opt/pki/.env

sudo -u pki softhsm2-util \
  --init-token \
  --free \
  --label "$SOFTHSM_TOKEN_LABEL" \
  --so-pin  "$SOFTHSM_SO_PIN" \
  --pin     "$SOFTHSM_USER_PIN"

# Verify the token was created
sudo -u pki softhsm2-util --show-slots
# Should show: Token Label: PkiCA, Initialized: yes
```

> **Note:** If you ever re-initialise the token, all keys stored in it are permanently
> destroyed. Back up the token directory `/var/lib/softhsm/tokens/` regularly.

---

## 7. Build Releases

Run on your **build machine** (not the server), or in CI. The build machine needs
Erlang/OTP and Elixir installed (same version as the server).

```bash
# On build machine — from repo root
# Source .env so signing salts are baked into the release at compile time
source .env

bash deploy/build.sh
```

This produces tarballs in `deploy/releases/`:
```
deploy/releases/
├── pki_ca_engine-0.1.0.tar.gz
├── pki_ra_engine-0.1.0.tar.gz
├── pki_ca_portal-0.1.0.tar.gz
├── pki_ra_portal-0.1.0.tar.gz
├── pki_platform_portal-0.1.0.tar.gz
└── pki_validation-0.1.0.tar.gz
```

### Copy tarballs to server

```bash
# From build machine
scp deploy/releases/*.tar.gz user@your-server:~/pki/deploy/releases/
```

---

## 8. Deploy Releases

Run on the server as root. This extracts releases, runs database migrations,
and starts all services:

```bash
cd ~/pki
sudo bash deploy/deploy.sh
```

Expected output:
```
[deploy] Deploying ca_engine from pki_ca_engine-0.1.0.tar.gz...
[deploy]   Stopping pki-ca-engine...
[deploy]   Extracted to /opt/pki/releases/ca_engine
[deploy]   Running migrations for ca_engine...
[deploy]   Started pki-ca-engine
[deploy]   ✓ pki-ca-engine is running
[deploy] Deploying validation from pki_validation-0.1.0.tar.gz...
...
[deploy] All services deployed.
```

---

## 9. Start All Services

After the first deploy, all services are enabled and started automatically.
For subsequent server reboots, systemd starts everything in order:

```
postgresql      (system)
  └── pki-ca-engine    (After=postgresql)
        ├── pki-ra-engine    (After=pki-ca-engine)
        ├── pki-ca-portal    (After=pki-ca-engine)
        └── pki-validation   (After=pki-ca-engine)
              └── pki-ra-portal     (After=pki-ra-engine)
pki-platform-portal    (After=postgresql)
caddy                  (After=pki-*-portal)
```

Start Caddy last (after all portals are up):
```bash
sudo systemctl start caddy
sudo systemctl enable caddy
```

Check everything is running:
```bash
systemctl status 'pki-*' caddy postgresql
```

---

## 10. Verify Deployment

### 10.1 Service health checks

```bash
# CA Engine API
curl -s http://localhost:4001/health
# Expected: {"status":"ok"}

# RA Engine API
curl -s http://localhost:4003/health
# Expected: {"status":"ok"}

# Validation Service
curl -s http://localhost:4005/health
# Expected: {"status":"ok"}

# CA Portal (through Caddy)
curl -sI https://ca.straptrust.com
# Expected: HTTP/2 200

# RA Portal
curl -sI https://ra.straptrust.com
# Expected: HTTP/2 200

# Platform Admin Portal
curl -sI https://admin.straptrust.com
# Expected: HTTP/2 200
```

### 10.2 TLS certificates

```bash
# Check Caddy issued Let's Encrypt certificates
echo | openssl s_client -connect ca.straptrust.com:443 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
```

### 10.3 CA Engine first-run setup

The CA Portal will redirect to `/setup` on first access (no users in DB yet):

```
https://ca.straptrust.com  →  /setup  (first run)
                            →  /login  (after setup)
```

Create the first admin account through the browser, then proceed with:
1. Configure a keystore (Software or HSM)
2. Run a key ceremony to generate root keys
3. Create issuer keys

### 10.4 RA Portal first-run setup

```
https://ra.straptrust.com  →  /setup  (first run)
```

Create the first admin account, then configure cert profiles and service configs.

---

## 11. Operations Reference

### View logs

```bash
# Follow logs for a service (structured, with request_id and remote_ip)
journalctl -u pki-ca-engine -f

# Last 100 lines
journalctl -u pki-ca-engine -n 100

# All PKI services since last boot
journalctl -u 'pki-*' -b

# Filter by time
journalctl -u pki-ca-engine --since "2026-03-29 10:00" --until "2026-03-29 11:00"
```

### Service control

```bash
# Status
systemctl status pki-ca-engine

# Restart a service (e.g. after config change)
systemctl restart pki-ca-engine

# Stop / Start
systemctl stop pki-ca-engine
systemctl start pki-ca-engine
```

### BEAM remote shell

Connect a live IEx shell to a running BEAM VM — no restart needed:

```bash
# Connect to CA Engine
sudo -u pki /opt/pki/releases/ca_engine/bin/pki_ca_engine remote

# Now you have a live IEx shell inside the running VM:
iex> PkiCaEngine.Repo.aggregate(PkiCaEngine.Schema.IssuerKey, :count)
iex> :observer.start()   # opens GUI process inspector (requires X11 forwarding)
iex> :erlang.memory()    # memory usage breakdown
iex> Node.list()         # connected BEAM nodes (if clustering)
iex> :q                  # disconnect (does NOT stop the service)
```

> **Important:** Typing `System.halt()` in the remote shell WILL stop the service.
> Use `:q` or Ctrl+C to disconnect safely.

### Run migrations manually

```bash
sudo bash ~/pki/deploy/deploy.sh migrate
```

Or for a single service:
```bash
sudo -u pki env $(grep -v '^#' /opt/pki/.env | xargs) \
  /opt/pki/releases/ca_engine/bin/pki_ca_engine eval \
  "PkiCaEngine.Release.migrate()"
```

### Check BEAM scheduler usage

```bash
# In the remote shell
iex> :scheduler.utilization(1000)  # sample schedulers for 1 second
```

Or install `observer_cli` for a terminal-based dashboard:
```bash
iex> :observer_cli.start()
```

### Check process count and memory

```bash
sudo -u pki /opt/pki/releases/ca_engine/bin/pki_ca_engine remote << 'IEX'
:erlang.system_info(:process_count) |> IO.inspect(label: "processes")
:erlang.memory() |> IO.inspect(label: "memory bytes")
IEX
```

---

## 12. Upgrading

For **zero-downtime upgrades** of a single service:

```bash
# On build machine — build a new release
source .env && bash deploy/build.sh

# Copy to server
scp deploy/releases/pki_ca_engine-0.2.0.tar.gz user@server:~/pki/deploy/releases/

# On server — upgrade only that service
sudo bash ~/pki/deploy/deploy.sh ca-engine
```

`deploy.sh` will:
1. Back up the current release to `ca_engine.bak`
2. Stop the service (graceful OTP shutdown — in-flight requests finish)
3. Extract the new release
4. Run any new migrations
5. Start the new version
6. Report health status

If something goes wrong:
```bash
sudo bash ~/pki/deploy/deploy.sh rollback ca-engine
```

### Hot code upgrades (advanced)

BEAM supports upgrading code **without restarting** the VM, which is valuable for
the CA Engine because it keeps activated keys in memory. This requires generating
`appup` files, which is an advanced OTP topic. For most upgrades, the stop/start
approach above is safe and fast enough.

---

## 13. Troubleshooting

### Service fails to start

```bash
# Check the last 50 log lines
journalctl -u pki-ca-engine -n 50 --no-pager

# Common causes:
# 1. .env variable missing or wrong value
# 2. PostgreSQL not running or wrong DATABASE_URL
# 3. Port already in use
# 4. Release binary not executable

# Check port conflicts
ss -tlnp | grep -E '400[1-6]'

# Check .env is readable by pki user
sudo -u pki cat /opt/pki/.env | head -5
```

### Database connection error

```bash
# Test connection directly
sudo -u pki psql "ecto://postgres:<pass>@localhost:5432/pki_ca_engine" -c '\l'

# Check PostgreSQL is listening
systemctl status postgresql
ss -tlnp | grep 5432
```

### SoftHSM2 / HSM errors

```bash
# Check pki user can see the token
sudo -u pki softhsm2-util --show-slots

# If token shows "Not initialized":
source /opt/pki/.env
sudo -u pki softhsm2-util --init-token --free \
  --label "$SOFTHSM_TOKEN_LABEL" \
  --so-pin "$SOFTHSM_SO_PIN" \
  --pin "$SOFTHSM_USER_PIN"

# Check library path exists
ls -la /usr/lib/softhsm/libsofthsm2.so
```

### Caddy not issuing TLS certificates

```bash
journalctl -u caddy -n 50

# Common causes:
# 1. DNS not yet propagated (check: dig +short ca.straptrust.com)
# 2. Port 80 blocked by firewall
# 3. CADDY_ACME_EMAIL not in .env (loaded from /opt/pki/.env via EnvironmentFile)

# Check firewall
ufw status
# Ensure 80 and 443 are ALLOW

# Manual test (Caddy HTTP challenge needs port 80 open)
curl -v http://ca.straptrust.com/.well-known/acme-challenge/test
```

### High memory usage

```bash
# Check per-service memory
systemctl status 'pki-*' | grep -E 'Memory|pki-'

# If a single VM is using too much, reduce pool_size in .env:
POOL_SIZE=5   # default is 10 DB connections per VM

# Then restart that service
systemctl restart pki-ca-engine
```

### BEAM scheduler saturation

```bash
# Check CPU usage per VM
top -p $(pgrep -d',' beam.smp)

# If all 6 VMs are pegging CPUs, the +S 2:2 limit may need tuning.
# Edit /etc/systemd/system/pki-ca-engine.service:
#   Environment=ELIXIR_ERL_OPTIONS=+S 1:1 +SDcpu 1
# Then: systemctl daemon-reload && systemctl restart pki-ca-engine
```

---

## Summary: Full Deployment Checklist

```
[ ] DNS A records created and propagated
[ ] sudo bash deploy/install.sh
[ ] sudo nano /opt/pki/.env  — all CHANGE_ME values replaced
[ ] Databases created (Section 5)
[ ] SoftHSM2 token initialised (Section 6)
[ ] source .env && bash deploy/build.sh  (on build machine)
[ ] scp deploy/releases/*.tar.gz  (copy to server)
[ ] sudo bash deploy/deploy.sh
[ ] sudo systemctl start caddy
[ ] curl https://ca.straptrust.com/health  → {"status":"ok"}
[ ] curl https://ra.straptrust.com/health  → {"status":"ok"}
[ ] https://ca.straptrust.com/setup  — create first CA admin
[ ] https://ra.straptrust.com/setup  — create first RA admin
[ ] https://admin.straptrust.com    — log in as trust_admin
[ ] Configure keystore in CA Portal
[ ] Run key ceremony
[ ] Create issuer keys
```
