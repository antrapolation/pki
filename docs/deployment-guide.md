# PQC Certificate Authority System — Deployment Guide

## Target Environment

| Component | Specification |
|-----------|--------------|
| **Server** | Ubuntu 24.04 LTS (8 vCPU, 24 GB RAM, 400 GB storage) |
| **Runtime** | Erlang/OTP 27 + Elixir 1.18 (native BEAM) |
| **Database** | PostgreSQL 17 (native install) |
| **HSM** | SoftHSM2 (native install, for pre-production testing) |
| **Reverse Proxy** | Caddy (automatic HTTPS via Let's Encrypt) |
| **Email** | Resend API (for invitation emails) |

### Architecture

All services run as native BEAM processes on a single server. No containers.

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
   │   :4006     │    │ ┌────────┐ │    │ ┌────────┐ │  │ OCSP / CRL │
   └─────┬───────┘    │ │CA Eng. │ │    │ │RA Eng. │ │  └────────────┘
         │            │ └────────┘ │    │ │CA Eng. │ │
         │            └─────┬──────┘    │ └────────┘ │
         │                  │           └─────┬──────┘
         │                  │                 │
         │            ┌─────▼─────────────────▼────┐
         │            │         SoftHSM2           │  PKCS#11 (native)
         │            └────────────────────────────┘
         │
   ┌─────▼──────────────────────────────────────────┐
   │                PostgreSQL 17                     │
   │  pki_platform    pki_tenant_{uuid} ...          │
   └─────────────────────────────────────────────────┘
```

> **Direct mode** (`ENGINE_CLIENT_MODE=direct`): Portals boot engines as OTP
> dependencies in the same BEAM node. No HTTP between portal and engine.

---

## 1. Server Setup

### 1.1 Create non-root user

```bash
ssh root@your-server-ip
adduser pki
usermod -aG sudo pki
su - pki
```

### 1.2 SSH key authentication

```bash
# On your local machine
ssh-copy-id pki@your-server-ip

# Then disable password login
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
# Set: PasswordAuthentication no
sudo systemctl restart ssh
```

### 1.3 Firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 1.4 System packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw build-essential autoconf m4 libncurses-dev \
  libssl-dev libwxgtk3.2-dev libgl1-mesa-dev libglu1-mesa-dev libpng-dev \
  unixodbc-dev xsltproc fop
```

---

## 2. Install Dependencies

### 2.1 PostgreSQL 17

```bash
sudo apt install -y postgresql-17 postgresql-client-17
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Set password
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'your-strong-password';"

# Increase max connections for multi-tenant
sudo nano /etc/postgresql/17/main/postgresql.conf
# Set: max_connections = 300
# Set: shared_buffers = 4GB
# Set: effective_cache_size = 12GB
# Set: work_mem = 16MB

sudo systemctl restart postgresql
```

### 2.2 Erlang/OTP + Elixir (via asdf)

```bash
git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch v0.14.0
echo '. "$HOME/.asdf/asdf.sh"' >> ~/.bashrc
source ~/.bashrc

asdf plugin add erlang
asdf plugin add elixir

asdf install erlang 27.2.3
asdf install elixir 1.18.4-otp-27
asdf global erlang 27.2.3
asdf global elixir 1.18.4-otp-27

# Verify
elixir --version
erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().'
```

### 2.3 Rust (for PKCS#11 NIF)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version  # should be 1.91+
```

### 2.4 SoftHSM2

```bash
sudo apt install -y softhsm2 opensc

# Create token directory
sudo mkdir -p /var/lib/softhsm/tokens
sudo chown pki:pki /var/lib/softhsm/tokens

# Configure
cat > ~/softhsm2.conf << 'EOF'
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF

export SOFTHSM2_CONF=~/softhsm2.conf
echo 'export SOFTHSM2_CONF=~/softhsm2.conf' >> ~/.bashrc

# Initialize token
softhsm2-util --init-token --free --label "PkiCA" \
  --so-pin <generated-so-pin> --pin <generated-user-pin>

# Verify
softhsm2-util --show-slots
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L

# Note the slot ID from the output — you'll need it for HSM device registration
```

### 2.5 Caddy

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

---

## 3. Deploy Application

### 3.1 Configure Git

The Gitea server uses a self-signed certificate. Configure Git to skip SSL verification and store credentials for both the main repo and all submodules.

**Step 1: Generate a Gitea personal access token**

1. Login to `https://vcs.antrapol.tech:3800`
2. Go to **Settings** → **Applications** → **Generate New Token**
3. Name: `pki-deploy`, Permissions: `repo` (read/write)
4. Copy the token — you'll use it as your password

**Step 2: Configure Git globally**

```bash
# Disable SSL verification for the Gitea server (self-signed cert)
git config --global http.https://vcs.antrapol.tech:3800/.sslVerify false

# Store credentials permanently (so you enter username/token only once)
git config --global credential.helper store

# Set your identity
git config --global user.name "your-gitea-username"
git config --global user.email "your-email@example.com"
```

**Step 3: Pre-store credentials** (so submodule clone doesn't prompt repeatedly)

```bash
# Write credentials to the store file directly
# Replace YOUR_USERNAME and YOUR_TOKEN with your actual values
cat >> ~/.git-credentials << 'EOF'
https://YOUR_USERNAME:YOUR_TOKEN@vcs.antrapol.tech:3800
EOF
chmod 600 ~/.git-credentials
```

This single entry covers both the main repo (`Incubator/pki.git`) and all submodules (`MDP/*.git`) since they share the same host.

### 3.2 Clone repository and submodules

```bash
cd /home/pki

# Clone main repo (credentials auto-read from ~/.git-credentials)
git clone https://vcs.antrapol.tech:3800/Incubator/pki.git
cd pki

# Clone all submodules (14 repos under MDP/ — same server, same credentials)
git submodule update --init --recursive

# Verify everything cloned
git submodule status
# Should show commit hashes for all 14 submodules (no - prefix = initialized)
```

### 3.3 Pulling updates

```bash
cd /home/pki/pki

# Pull main repo
git pull

# Update all submodules to match main repo's recorded commits
git submodule update --recursive

# Or if submodules need to pull latest from their own branches:
git submodule foreach 'git pull origin main || git pull origin master || true'
```

### 3.4 Troubleshooting Git

```bash
# If submodule clone fails with SSL error:
git config --global http.sslVerify false  # nuclear option: disable for ALL hosts

# If prompted for credentials during submodule update:
# Verify ~/.git-credentials contains the correct entry:
cat ~/.git-credentials
# Should show: https://username:token@vcs.antrapol.tech:3800

# If a submodule is stuck or corrupted:
git submodule deinit -f src/problem_submodule
git submodule update --init src/problem_submodule

# List all submodule URLs (should all be vcs.antrapol.tech:3800):
git config --file .gitmodules --get-regexp url
```

### 3.5 Environment file

```bash
cat > /home/pki/pki/.env << 'EOF'
# ── PKI CA System — Production Environment ────────────────────────────────
# All CHANGE_ME values must be replaced before first boot.

# ── Architecture Mode ────────────────────────────────────────────────────
# "direct" = single BEAM node, portals call engines in-process (no HTTP between services)
# Remove or set empty for multi-node HTTP mode
ENGINE_CLIENT_MODE=direct

# ── Database (PostgreSQL 17 on localhost) ────────────────────────────────
# Generate password: openssl rand -base64 24
CA_ENGINE_DATABASE_URL=ecto://postgres:CHANGE_ME@localhost:5432/pki_ca_engine
RA_ENGINE_DATABASE_URL=ecto://postgres:CHANGE_ME@localhost:5432/pki_ra_engine
VALIDATION_DATABASE_URL=ecto://postgres:CHANGE_ME@localhost:5432/pki_validation
PLATFORM_DATABASE_URL=ecto://postgres:CHANGE_ME@localhost:5432/pki_platform

# ── Shared Secrets ───────────────────────────────────────────────────────
# Generate: openssl rand -base64 64
SECRET_KEY_BASE=CHANGE_ME

# Generate: openssl rand -base64 32
INTERNAL_API_SECRET=CHANGE_ME

# ── Portal Session Salts (one per portal) ────────────────────────────────
# Generate each: openssl rand -base64 32
CA_PORTAL_SIGNING_SALT=CHANGE_ME
RA_PORTAL_SIGNING_SALT=CHANGE_ME
RA_PORTAL_ENCRYPTION_SALT=CHANGE_ME
PLATFORM_SIGNING_SALT=CHANGE_ME

# ── Platform Admin (optional — only if you want env-based seeding) ─────
# If omitted, the /setup page will prompt for admin creation on first boot.
# PLATFORM_ADMIN_USERNAME=admin
# PLATFORM_ADMIN_PASSWORD=CHANGE_ME

# ── Portal Hostnames (must match Caddy/DNS) ─────────────────────────────
PHX_HOST=straptrust.com
CA_PORTAL_HOST=ca.straptrust.com
RA_PORTAL_HOST=ra.straptrust.com
PLATFORM_HOST=admin.straptrust.com

# ── Portal URL (for invitation emails) ──────────────────────────────────
PLATFORM_PORTAL_URL=https://admin.straptrust.com

# ── Email (Resend) ──────────────────────────────────────────────────────
RESEND_API_KEY=CHANGE_ME
MAILER_FROM=PQC PKI Platform <noreply@straptrust.com>

# ── Service Ports ────────────────────────────────────────────────────────
CA_PORTAL_PORT=4002
RA_PORTAL_PORT=4004
PORT=4006

# ── Internal Service URLs (only needed if ENGINE_CLIENT_MODE is NOT direct)
CA_ENGINE_URL=http://127.0.0.1:4001
RA_ENGINE_URL=http://127.0.0.1:4003
VALIDATION_URL=http://127.0.0.1:4005

# ── Connection Pool ─────────────────────────────────────────────────────
POOL_SIZE=10
TENANT_POOL_SIZE=2

# ── Security ────────────────────────────────────────────────────────────
COOKIE_SECURE=true

# ── HSM ─────────────────────────────────────────────────────────────────
SOFTHSM2_CONF=/home/pki/softhsm2.conf
EOF
```

Generate secrets:

```bash
openssl rand -base64 64   # SECRET_KEY_BASE
openssl rand -base64 32   # INTERNAL_API_SECRET, salts
openssl rand -base64 24   # PostgreSQL password
openssl rand -hex 4       # SoftHSM SO PIN
openssl rand -hex 4       # SoftHSM User PIN
```

### 3.6 Create databases

```bash
sudo -u postgres psql << SQL
CREATE DATABASE pki_platform;
CREATE DATABASE pki_ca_engine;
CREATE DATABASE pki_ra_engine;
CREATE DATABASE pki_validation;
SQL
```

### 3.7 Fetch dependencies and compile

```bash
cd /home/pki/pki

# Fetch deps for all services
for dir in src/pki_platform_engine src/pki_ca_engine src/pki_ra_engine \
           src/pki_validation \
           src/pki_platform_portal src/pki_ca_portal src/pki_ra_portal; do
  echo "=== $dir ==="
  (cd $dir && MIX_ENV=prod mix deps.get && MIX_ENV=prod mix compile)
done
```

The PKCS#11 Rust NIF compiles automatically during `mix compile` of `strap_softhsm_priv_key_store_provider`.

### 3.8 Run migrations

```bash
source /home/pki/pki/.env

cd /home/pki/pki/src/pki_platform_engine && \
  MIX_ENV=prod mix ecto.migrate --repo PkiPlatformEngine.PlatformRepo

cd /home/pki/pki/src/pki_ca_engine && MIX_ENV=prod mix ecto.migrate

cd /home/pki/pki/src/pki_ra_engine && MIX_ENV=prod mix ecto.migrate

cd /home/pki/pki/src/pki_validation && MIX_ENV=prod mix ecto.migrate
```

---

## 4. Service Management (systemd)

In Direct mode (`ENGINE_CLIENT_MODE=direct`), portals boot their engines as OTP dependencies. There are no separate CA Engine or RA Engine services. Only **4 systemd units** are needed:

| Service | Port | What it runs |
|---------|------|--------------|
| Platform Portal | 4006 | Phoenix + platform engine + all tenant engines |
| CA Portal | 4002 | Phoenix + CA engine in-process |
| RA Portal | 4004 | Phoenix + RA engine + CA engine in-process |
| Validation | 4005 | Plug.Cowboy (OCSP/CRL, not Phoenix) |

### 4.1 Platform Portal (port 4006 — starts tenant engines)

This is the most critical service — it boots all tenant engines on startup.

```bash
sudo cat > /etc/systemd/system/pki-platform-portal.service << 'EOF'
[Unit]
Description=PQC PKI Platform Portal
After=postgresql.service network.target
Requires=postgresql.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_platform_portal
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=prod
ExecStart=/home/pki/.asdf/shims/elixir --sname platform_portal -S mix phx.server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.2 CA Portal (port 4002 — includes CA Engine)

```bash
sudo cat > /etc/systemd/system/pki-ca-portal.service << 'EOF'
[Unit]
Description=PQC PKI CA Portal (includes CA Engine)
After=postgresql.service pki-platform-portal.service
Requires=postgresql.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_ca_portal
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=prod
ExecStart=/home/pki/.asdf/shims/elixir --sname ca_portal -S mix phx.server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.3 RA Portal (port 4004 — includes RA Engine + CA Engine)

```bash
sudo cat > /etc/systemd/system/pki-ra-portal.service << 'EOF'
[Unit]
Description=PQC PKI RA Portal (includes RA Engine + CA Engine)
After=postgresql.service pki-platform-portal.service
Requires=postgresql.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_ra_portal
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=prod
ExecStart=/home/pki/.asdf/shims/elixir --sname ra_portal -S mix phx.server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.4 Validation Service (port 4005 — OCSP/CRL)

The validation service is a standalone Plug.Cowboy app (not Phoenix). It serves OCSP responder and CRL endpoints.

```bash
sudo cat > /etc/systemd/system/pki-validation.service << 'EOF'
[Unit]
Description=PQC PKI Validation Service (OCSP/CRL)
After=postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_validation
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=prod
ExecStart=/home/pki/.asdf/shims/elixir --sname validation -S mix run --no-halt
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.5 Enable and start all services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pki-platform-portal
sleep 5
sudo systemctl enable --now pki-ca-portal
sudo systemctl enable --now pki-ra-portal
sudo systemctl enable --now pki-validation
```

### 4.6 Service management commands

```bash
# Check status
sudo systemctl status pki-platform-portal
sudo systemctl status pki-ca-portal
sudo systemctl status pki-ra-portal
sudo systemctl status pki-validation

# View logs
sudo journalctl -u pki-platform-portal -f
sudo journalctl -u pki-ca-portal --since "5 minutes ago"

# Restart a service
sudo systemctl restart pki-ca-portal

# Restart all
sudo systemctl restart pki-platform-portal pki-ca-portal pki-ra-portal pki-validation

# Stop all (reverse order)
sudo systemctl stop pki-validation pki-ra-portal pki-ca-portal pki-platform-portal
```

---

## 5. Caddy HTTPS Configuration

### 5.1 DNS records

Point these domains to your server IP:

| Domain | Service |
|--------|---------|
| `admin.straptrust.com` | Platform Portal (:4006) |
| `ca.straptrust.com` | CA Portal (:4002) |
| `ra.straptrust.com` | RA Portal (:4004) |
| `ocsp.straptrust.com` | Validation (:4005) |

### 5.2 Caddyfile

```bash
sudo nano /etc/caddy/Caddyfile
```

```
admin.straptrust.com {
    reverse_proxy localhost:4006
}

ca.straptrust.com {
    reverse_proxy localhost:4002
}

ra.straptrust.com {
    reverse_proxy localhost:4004
}

ocsp.straptrust.com {
    reverse_proxy localhost:4005
}
```

```bash
sudo systemctl restart caddy
sudo systemctl enable caddy
```

Caddy auto-provisions Let's Encrypt certificates.

### 5.3 Security Notes

- **All services listen on plain HTTP (localhost only).** TLS termination is handled by Caddy.
- **Do not expose internal ports (4002-4006) to the internet.** Only ports 80/443 should be open in the firewall.
- In Direct mode, there is no inter-service HTTP traffic. Portals call engines via in-process Elixir function calls (OTP). This eliminates an entire class of network-level vulnerabilities.
- The RA Portal exposes API endpoints for external API key clients at `ra.straptrust.com` through Caddy. Caddy handles TLS for this traffic.

---

## 6. HSM Configuration

### 6.1 SoftHSM2 (pre-production)

SoftHSM2 is installed natively. Key details:

| Setting | Value |
|---------|-------|
| Config file | `/home/pki/softhsm2.conf` |
| Token directory | `/var/lib/softhsm/tokens` |
| PKCS#11 library | `/usr/lib/softhsm/libsofthsm2.so` |
| Token label | `PkiCA` |
| SO PIN | `<your-generated-pin>` |
| User PIN | `<your-generated-pin>` |

The `SOFTHSM2_CONF` env var must be set for all services that access the HSM.

### 6.2 Register HSM in Platform Portal

After deployment, register SoftHSM2 as an HSM device:

1. Login to Platform Portal (`https://admin.straptrust.com`)
2. Go to **HSM Devices** → Register:
   - Label: `SoftHSM2 Pre-Production`
   - PKCS#11 Library Path: `/usr/lib/softhsm/libsofthsm2.so`
   - Slot ID: `<slot from softhsm2-util --show-slots>`
3. System probes the library and confirms manufacturer
4. Go to **Tenants** → select tenant → **HSM Device Access** → assign the device

### 6.3 Upgrading to Hardware HSM (production)

When moving to a real HSM (Thales Luna, YubiHSM 2, etc.):

1. Install vendor's PKCS#11 driver on the server
2. Register the new HSM device in Platform Portal with the vendor's library path:
   - Thales Luna: `/usr/lib/libCryptoki2_64.so`
   - YubiHSM 2: `/usr/lib/libyubihsm_pkcs11.so`
   - AWS CloudHSM: `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`
3. Assign to tenants
4. Optionally deactivate SoftHSM2 (revoke all tenant access first)

Zero code changes needed — the PKCS#11 interface is the same.

---

## 7. Email Configuration (Resend)

Invitation emails are sent when:
- Platform admin creates a new platform admin
- CA/RA admin creates a new user
- Password reset or invitation resend

### 7.1 Setup Resend

1. Sign up at [resend.com](https://resend.com)
2. Verify your domain (e.g., `straptrust.com`)
3. Create an API key
4. Set in `.env`:

```ini
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxx
MAILER_FROM=PQC PKI Platform <noreply@straptrust.com>
```

### 7.2 Without Resend

If `RESEND_API_KEY` is not set, emails are silently skipped (`{:ok, :skipped}`). Users can still be created — they just won't receive invitation emails. The admin must communicate credentials manually.

---

## 8. Environment Variables Reference

### Architecture

| Variable | Required | Description |
|----------|----------|-------------|
| `ENGINE_CLIENT_MODE` | Yes | `direct` for single-node BEAM (portals boot engines in-process) |

### Database

| Variable | Required | Description |
|----------|----------|-------------|
| `CA_ENGINE_DATABASE_URL` | Yes | Ecto URL for CA engine database |
| `RA_ENGINE_DATABASE_URL` | Yes | Ecto URL for RA engine database |
| `VALIDATION_DATABASE_URL` | Yes | Ecto URL for validation database |
| `PLATFORM_DATABASE_URL` | Yes | Ecto URL for platform database |
| `POOL_SIZE` | No | Default: 10 (DB connection pool per repo) |
| `TENANT_POOL_SIZE` | No | Default: 2 (DB pool per dynamic tenant repo) |

### Shared Secrets

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY_BASE` | Yes | 64+ byte secret for session signing |
| `INTERNAL_API_SECRET` | Yes | Shared secret for service-to-service auth |

### Portal Session Salts

| Variable | Required | Description |
|----------|----------|-------------|
| `CA_PORTAL_SIGNING_SALT` | Yes | Signing salt for CA portal sessions |
| `RA_PORTAL_SIGNING_SALT` | Yes | Signing salt for RA portal sessions |
| `RA_PORTAL_ENCRYPTION_SALT` | Yes | Encryption salt for RA portal sessions |
| `PLATFORM_SIGNING_SALT` | Yes | Signing salt for platform portal sessions |

### Platform Portal (:4006)

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Default: 4006 |
| `PLATFORM_HOST` | Yes | Hostname for platform portal |
| `PLATFORM_ADMIN_USERNAME` | No | Optional env-based admin seeding (setup page is preferred) |
| `PLATFORM_ADMIN_PASSWORD` | Yes | Initial superadmin password |
| `PLATFORM_PORTAL_URL` | Yes | Full URL for invitation email links |
| `RESEND_API_KEY` | No | Resend.com API key for emails |

### CA Portal (:4002)

| Variable | Required | Description |
|----------|----------|-------------|
| `CA_PORTAL_PORT` | No | Default: 4002 |
| `CA_PORTAL_HOST` | Yes | Hostname for CA portal |
| `COOKIE_SECURE` | No | `true` for HTTPS, `false` for localhost HTTP |
| `RESEND_API_KEY` | No | For user invitation emails |

### RA Portal (:4004)

| Variable | Required | Description |
|----------|----------|-------------|
| `RA_PORTAL_PORT` | No | Default: 4004 |
| `RA_PORTAL_HOST` | Yes | Hostname for RA portal |
| `COOKIE_SECURE` | No | Same as CA Portal |
| `RESEND_API_KEY` | No | For user invitation emails |

### Internal Service URLs (multi-node HTTP mode only)

These are only needed when `ENGINE_CLIENT_MODE` is **not** `direct`:

| Variable | Required | Description |
|----------|----------|-------------|
| `CA_ENGINE_URL` | Conditional | `http://127.0.0.1:4001` |
| `RA_ENGINE_URL` | Conditional | `http://127.0.0.1:4003` |
| `VALIDATION_URL` | Conditional | `http://127.0.0.1:4005` |

### HSM & Security

| Variable | Required | Description |
|----------|----------|-------------|
| `SOFTHSM2_CONF` | Yes | Path to SoftHSM2 config file |
| `COOKIE_SECURE` | No | `true` for HTTPS (default), `false` for dev |

### Email

| Variable | Required | Description |
|----------|----------|-------------|
| `RESEND_API_KEY` | No | Resend.com API key (emails skipped if unset) |
| `MAILER_FROM` | No | From address for outbound emails |

---

## 9. Database Capacity

### Connection Budget

| Setting | Value |
|---------|-------|
| PostgreSQL max_connections | 300 |
| Fixed overhead (all services) | ~30 connections |
| Per tenant | ~6 connections |
| **Max tenants** | **~45** |

To support more tenants:
- Increase `max_connections` to 500 → ~78 tenants
- Add PgBouncer (transaction pooling) → 100+ tenants
- Reduce `TENANT_POOL_SIZE` to 1 → double capacity

### Backup

```bash
#!/bin/bash
# /home/pki/backup.sh
DATE=$(date +%Y%m%d_%H%M)
BACKUP_DIR=/home/pki/backups/$DATE
mkdir -p $BACKUP_DIR

# Platform database
sudo -u postgres pg_dump pki_platform | gzip > $BACKUP_DIR/pki_platform.sql.gz

# All tenant databases
for db in $(sudo -u postgres psql -t -c "SELECT datname FROM pg_database WHERE datname LIKE 'pki_tenant_%'"); do
  db=$(echo $db | xargs)
  sudo -u postgres pg_dump $db | gzip > $BACKUP_DIR/${db}.sql.gz
done

echo "Backup complete: $BACKUP_DIR"
find /home/pki/backups -maxdepth 1 -mtime +30 -exec rm -rf {} \;
```

```bash
# Daily cron
crontab -e
0 2 * * * /home/pki/backup.sh >> /home/pki/backups/cron.log 2>&1
```

---

## 10. Initial Setup Flow

After deployment:

### 10.1 Platform Admin

1. Navigate to `https://admin.straptrust.com`
2. On first boot, the system redirects to the **Setup Page** (`/setup`)
3. Create the initial admin: enter username, display name, and password
4. Login with the credentials you just created

### 10.2 Register HSM Device

1. Go to **HSM Devices** → Register SoftHSM2 (see Section 6.2)

### 10.3 Create Tenant

1. Go to **Tenants** → **New Tenant**
2. Enter organization name, slug, email
3. System provisions a dedicated database
4. **Activate** the tenant → engines start, admin credentials emailed

### 10.4 Assign HSM to Tenant

1. Go to **Tenants** → click tenant → **HSM Device Access**
2. Click the HSM device button to grant access

### 10.5 Tenant Admin Login

1. Tenant admin receives email with temporary credentials
2. Login at `https://ca.straptrust.com` or `https://ra.straptrust.com`
3. Forced to change password on first login
4. Begin CA/RA operations

---

## 11. Health Checks

```bash
# All portals
for port in 4002 4004 4006; do
  echo "Port $port: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:$port/login)"
done

# Validation service
echo "Port 4005: $(curl -s http://localhost:4005/health)"

# PostgreSQL
sudo -u postgres pg_isready

# SoftHSM2
softhsm2-util --show-slots
```

---

## 12. Update / Deploy New Version

```bash
cd /home/pki/pki
git pull
git submodule update --recursive

# Stop services (reverse order)
sudo systemctl stop pki-validation pki-ra-portal pki-ca-portal pki-platform-portal

# Recompile all services
for dir in src/pki_platform_engine src/pki_ca_engine src/pki_ra_engine \
           src/pki_validation src/pki_ca_portal src/pki_ra_portal \
           src/pki_platform_portal; do
  (cd $dir && MIX_ENV=prod mix deps.get && MIX_ENV=prod mix compile)
done

# Run migrations
cd src/pki_platform_engine && MIX_ENV=prod mix ecto.migrate --repo PkiPlatformEngine.PlatformRepo
cd ../pki_ca_engine && MIX_ENV=prod mix ecto.migrate
cd ../pki_ra_engine && MIX_ENV=prod mix ecto.migrate
cd ../pki_validation && MIX_ENV=prod mix ecto.migrate
cd ../..

# Restart services
sudo systemctl start pki-platform-portal
sleep 5
sudo systemctl start pki-ca-portal pki-ra-portal pki-validation
```

---

## 13. Security Checklist

### Before Go-Live

- [ ] All `.env` values changed from defaults
- [ ] `SECRET_KEY_BASE` generated with `openssl rand -base64 64`
- [ ] `INTERNAL_API_SECRET` generated with `openssl rand -base64 32`
- [ ] Strong PostgreSQL password set
- [ ] SoftHSM2 PINs generated randomly
- [ ] `RESEND_API_KEY` configured for email
- [ ] `COOKIE_SECURE=true` set for HTTPS
- [ ] DNS records configured for all subdomains
- [ ] Caddy running with valid SSL certificates
- [ ] Firewall configured (only 22, 80, 443 open)
- [ ] SSH root login disabled, key-only auth
- [ ] All health endpoints returning OK
- [ ] Database migrations run
- [ ] Platform admin can login
- [ ] At least one tenant created and activated
- [ ] HSM device registered and assigned to tenant
- [ ] Tenant admin can login and change password
- [ ] Daily backup cron configured

### Ongoing

- [ ] Monitor `journalctl -u pki-*` for errors
- [ ] Monitor disk usage (`df -h`)
- [ ] Monitor PostgreSQL connections (`SELECT count(*) FROM pg_stat_activity`)
- [ ] Review audit logs via CA Portal
- [ ] Rotate `INTERNAL_API_SECRET` periodically
- [ ] Keep OS, Erlang, and Elixir updated
- [ ] Test backup restore quarterly

---

## 14. Troubleshooting

### Service won't start

```bash
sudo journalctl -u pki-ca-portal -n 50
# Common: missing deps → cd into service dir, run MIX_ENV=prod mix deps.get
```

### Too many DB connections

```bash
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity;"
# If near max_connections, either:
# 1. Reduce POOL_SIZE/TENANT_POOL_SIZE in .env
# 2. Increase max_connections in postgresql.conf
```

### HSM probe fails

```bash
# Verify SOFTHSM2_CONF is set
echo $SOFTHSM2_CONF

# Verify library exists
ls -la /usr/lib/softhsm/libsofthsm2.so

# Test directly
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L
```

### Email not sending

```bash
# Check if RESEND_API_KEY is set
grep RESEND_API_KEY /home/pki/pki/.env

# Check logs for email errors
sudo journalctl -u pki-platform-portal | grep -i "email\|resend\|mailer"
```

### Slow page loads

```bash
# Check PostgreSQL connection saturation
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity;"

# Check service memory
ps aux | grep beam | awk '{print $6/1024 " MB", $11}'
```

---

## 15. Resource Sizing

| Component | CPU | RAM | Disk |
|-----------|-----|-----|------|
| PostgreSQL | 2 cores | 8 GB | Scales with tenants |
| Platform Portal + Tenant Engines | 2 cores | 2 GB | Minimal |
| CA Portal (includes CA Engine) | 1.5 cores | 1.5 GB | Minimal |
| RA Portal (includes RA + CA Engine) | 1.5 cores | 1.5 GB | Minimal |
| Validation (OCSP/CRL) | 0.5 core | 256 MB | Minimal |
| SoftHSM2 | — | — | Token files only |
| **Total** | ~7.5 cores | ~13 GB | ~20 GB initial |

Fits comfortably on the 8 vCPU / 24 GB / 400 GB server with headroom for 20-45 tenants.

---

## 16. Tenant Schema Migrations

The system includes an automated tenant migration system. Numbered SQL files in `src/pki_platform_engine/priv/tenant_migrations/` are applied to all tenant databases on application boot.

### How it works

1. Platform boots → `TenantMigrator.migrate_all()` runs
2. Queries all tenants (active + suspended) from `tenants` table
3. For each tenant, reads applied versions from `tenant_schema_versions`
4. Applies pending SQL migrations in order, wrapped in a transaction
5. Records the version on success

### Adding a new tenant migration

```bash
# Create a numbered SQL file
cat > src/pki_platform_engine/priv/tenant_migrations/004_your_migration.sql << 'SQL'
-- Description of what this migration does
ALTER TABLE ra.your_table ADD COLUMN IF NOT EXISTS new_column varchar;
SQL
```

Rules:
- Filename format: `NNN_description.sql` (NNN is zero-padded number)
- Statements are split on `;\n` and executed individually
- All statements run in a single transaction (rollback on failure)
- Use `IF NOT EXISTS` / `IF EXISTS` for idempotency
- Test on dev first: `cd src/pki_platform_engine && mix run -e 'PkiPlatformEngine.TenantMigrator.migrate_all()'`

### Also update the base schema dump

New tenant databases are created from `src/pki_platform_engine/priv/tenant_ra_schema.sql`. When adding columns to existing tables, update both the migration file AND the schema dump.

### Current migrations

| Version | Description |
|---------|-------------|
| 001 | Phase A: API key fields, approval_mode, submitted_by_key_id |
| 002 | Webhook delivery tracking table |
| 003 | Unique index on ra_api_keys.hashed_key |

---

## 17. API Key Management

### Key Types

| Type | Permissions |
|------|-------------|
| **Client** | submit_csr, view_csr, view_certificates |
| **Service** | All client + revoke_certificate, manage_dcv |

Approve/reject CSR operations are portal-only (not available via API keys).

### Enforcement Chain

All API requests pass through: `AuthPlug → IpWhitelistPlug → RbacPlug → ApiKeyScopePlug → Controller`

- **Rate limiting**: Per-key, Hammer-backed, fail-closed on backend error (503)
- **IP whitelist**: CIDR-based (IPv4/IPv6), empty = allow all, proxy-aware via X-Forwarded-For
- **Scope**: Key type determines allowed operations
- **Profile restriction**: `allowed_profile_ids` limits which cert profiles a key can submit CSRs for

### Webhook Delivery

API keys with `webhook_url` + `webhook_secret` receive HTTPS callbacks for CSR/cert lifecycle events. See `docs/webhook-reference.md` for full documentation.

- HMAC-SHA256 signed (timestamp-bound, `sha256=` prefix)
- 3 retries with exponential backoff (1s, 5s, 30s)
- Delivery attempts persisted in `webhook_deliveries` table
- Dead letters visible in portal API key detail panel

---

## 18. Telemetry & Monitoring

### Metrics Endpoint

```bash
# Authenticated with INTERNAL_API_SECRET (via RA Portal in Direct mode)
curl -H "Authorization: $INTERNAL_API_SECRET" http://localhost:4004/metrics
```

Returns JSON counters for:
- `pki.ra.auth.success`, `pki.ra.auth.failure`
- `pki.ra.rate_limit.allow`, `pki.ra.rate_limit.deny`
- `pki.ra.ip_whitelist.allow`, `pki.ra.ip_whitelist.deny`
- `pki.ra.scope.allow`, `pki.ra.scope.deny`
- `pki.ra.csr.submitted`, `pki.ra.csr.approved`, `pki.ra.csr.rejected`, `pki.ra.csr.issued`
- `pki.ra.webhook.delivered`, `pki.ra.webhook.failed`, `pki.ra.webhook.exhausted`
- `pki.ra.audit.failed`

### Health Endpoints

| Service | Endpoint | Expected |
|---------|----------|----------|
| Platform Portal | `http://localhost:4006/login` | HTTP 200 |
| CA Portal | `http://localhost:4002/login` | HTTP 200 |
| RA Portal | `http://localhost:4004/login` | HTTP 200 |
| Validation | `http://localhost:4005/health` | `{"status":"ok"}` |

### CSR Reconciler

The `CsrReconciler` GenServer sweeps every 5 minutes for CSRs stuck in "approved" status for >10 minutes. It retries `forward_to_ca` for each stuck CSR. Disable in config:

```elixir
config :pki_ra_engine, start_csr_reconciler: false
```

---

## 19. Architecture Modes

### Direct Mode (default, recommended)

Set `ENGINE_CLIENT_MODE=direct` in `.env`. Portals boot engines as OTP dependencies in the same BEAM node. No HTTP between portal and engine. This is the mode documented throughout this guide.

### Multi-Node HTTP Mode

Remove or leave `ENGINE_CLIENT_MODE` empty. Each engine runs as a separate process with its own HTTP server. Portals communicate with engines via HTTP using `CA_ENGINE_URL`, `RA_ENGINE_URL`, and `VALIDATION_URL`. This mode requires additional systemd services for the engines and is intended for distributed multi-server deployments.

### Dev Configuration

In `config/dev.exs`, Direct mode is enabled by default:

```elixir
# Engines run in-process, no HTTP servers needed
config :pki_ra_engine, start_http: false
config :pki_ca_engine, :start_http, false

# Use Direct CA client (in-process signing)
config :pki_ra_engine, :ca_engine_module, PkiRaEngine.CsrValidation.DirectCaClient

# Dev-only: auto-activate issuer keys on boot (bypass threshold ceremony)
config :pki_ca_engine, :dev_auto_activate_keys, true
```

### Start commands (dev)

```bash
# Must use --sname for PQC NIF (KAZ-SIGN) and Erlang distribution
elixir --sname ra_portal -S mix phx.server
```

The validation service is a Plug.Cowboy app, not Phoenix:

```bash
elixir --sname validation -S mix run --no-halt
```

---

## 20. KAZ-SIGN (Post-Quantum) Configuration

KAZ-SIGN uses a native C NIF wrapper (not JRuby). The NIF binary is at `src/pki_oqs_nif/priv/oqs_nif.so` and the KAZ-SIGN library is linked from `PQC-KAZ/SIGN/bindings/elixir`.

### Security Levels

| Algorithm | Security | Key Size |
|-----------|----------|----------|
| KAZ-SIGN-128 | 128-bit | SHA-256 based |
| KAZ-SIGN-192 | 192-bit | SHA-384 based |
| KAZ-SIGN-256 | 256-bit | SHA-512 based |

### Key Activation

Issuer keys require activation before signing. In production, this uses threshold secret sharing (Shamir):

1. CA admin initiates key ceremony (generate keypair, split into N shares)
2. K custodians each submit their share + password to reconstruct the key
3. Key is held in memory with a configurable timeout (default: 1 hour)
4. After timeout, key is wiped from memory and must be re-activated

In dev mode with `dev_auto_activate_keys: true`, keys are auto-generated and injected on boot.

### Integration Test

```bash
cd src/pki_ra_portal
elixir --sname int_test -S mix run ../../scripts/integration_test.exs
```

Tests the full CSR lifecycle: generate CSR → submit → validate → approve → KAZ-SIGN NIF sign → issue certificate.

---

## 21. Security Checklist (Updated)

### API Security

- [ ] `/metrics` endpoint requires `INTERNAL_API_SECRET` auth
- [ ] Request body size limited to 1MB (`Plug.Parsers length: 1_000_000`)
- [ ] API key `hashed_key` and `status` cannot be modified via update endpoint
- [ ] Rate limiter fails closed (503 on backend error)
- [ ] RBAC uses allowlist pattern (`== "ra_admin"`, not `!= "ra_admin"`)
- [ ] Approve/reject routes blocked for all API key types (portal-only)
- [ ] `webhook_secret` stored in DB (encrypt at rest for production)
- [ ] Submit buttons have `phx-disable-with` to prevent double-submit

### Operational Security

- [ ] Unique index on `ra_api_keys.hashed_key`
- [ ] Tenant migrations run in transactions with rollback
- [ ] CSR reconciler sweeps all tenants (active + suspended)
- [ ] Audit failures emit telemetry events
- [ ] Service config URLs validated for http/https scheme

---

## 22. Reset — Clear All Databases and Start Fresh

> **WARNING: This permanently destroys ALL data** — tenants, certificates, keys, users, audit logs. Only use for development reset or pre-production wipe.

### 22.1 Stop all services

```bash
# Systemd (production)
sudo systemctl stop pki-validation pki-ra-portal pki-ca-portal pki-platform-portal

# Or kill dev processes
pkill -9 -f "beam.smp"
```

### 22.2 Drop all databases

```bash
# Find and drop all tenant databases
sudo -u postgres psql -t -c "SELECT datname FROM pg_database WHERE datname LIKE 'pki_tenant_%'" | while read db; do
  db=$(echo $db | xargs)
  if [ -n "$db" ]; then
    echo "Dropping $db..."
    sudo -u postgres dropdb "$db"
  fi
done

# Drop core databases
sudo -u postgres dropdb pki_platform
sudo -u postgres dropdb pki_ca_engine
sudo -u postgres dropdb pki_ra_engine
sudo -u postgres dropdb pki_validation

echo "All PKI databases dropped."
```

For Podman/Docker (dev):

```bash
# If PostgreSQL runs in a container
podman exec -it pki-postgres psql -U postgres -c "
  SELECT 'DROP DATABASE ' || datname || ';'
  FROM pg_database
  WHERE datname LIKE 'pki_%'
" -t | podman exec -i pki-postgres psql -U postgres
```

### 22.3 Clear SoftHSM2 tokens

```bash
# Remove all HSM token data
rm -rf /var/lib/softhsm/tokens/*    # production
rm -rf softhsm2/tokens/*            # dev (repo-local)

# Re-initialize token
softhsm2-util --init-token --free --label "PkiCA" \
  --so-pin <your-so-pin> --pin <your-user-pin>

# Verify
softhsm2-util --show-slots
```

### 22.4 Recreate databases

```bash
sudo -u postgres psql << SQL
CREATE DATABASE pki_platform;
CREATE DATABASE pki_ca_engine;
CREATE DATABASE pki_ra_engine;
CREATE DATABASE pki_validation;
SQL
```

For dev (Podman):

```bash
podman exec -it pki-postgres psql -U postgres -c "
  CREATE DATABASE pki_platform;
  CREATE DATABASE pki_ca_engine;
  CREATE DATABASE pki_ra_engine;
  CREATE DATABASE pki_validation;
"
```

### 22.5 Run all migrations

```bash
cd /home/pki/pki   # or your repo root

source .env 2>/dev/null  # production

# Platform engine (creates tenant_schema_versions table)
cd src/pki_platform_engine && MIX_ENV=prod mix ecto.migrate --repo PkiPlatformEngine.PlatformRepo && cd ..

# CA engine (creates issuer_keys, ca_instances, ceremonies, etc.)
cd pki_ca_engine && MIX_ENV=prod mix ecto.migrate && cd ..

# RA engine (creates cert_profiles, csr_requests, api_keys, webhooks, etc.)
cd pki_ra_engine && MIX_ENV=prod mix ecto.migrate && cd ..

# Validation (creates certificate_statuses, etc.)
cd pki_validation && MIX_ENV=prod mix ecto.migrate && cd ../..

echo "All migrations complete."
```

### 22.6 Start services

```bash
# Production (systemd)
sudo systemctl start pki-platform-portal
sleep 5
sudo systemctl start pki-ca-portal pki-ra-portal pki-validation
```

For dev, see [Section 19: Single-Node Deployment](#19-single-node-portal-deployment-mode).

### 22.7 Re-do initial setup

After a full reset, you must repeat the initial setup:

1. **Platform admin** — navigate to the platform portal, complete the `/setup` page to create the first admin
2. **Register HSM device** — Platform Portal → HSM Devices → Register SoftHSM2
3. **Create tenant** — Platform Portal → Tenants → New Tenant → Activate
4. **Assign HSM to tenant** — Tenants → tenant → HSM Device Access
5. **Tenant admin login** — CA Portal or RA Portal with emailed/manual credentials
6. **Key ceremony** — CA Portal → create CA instance → generate issuer key → distribute shares
7. **RA setup** — RA Portal → setup wizard → connect CA key → create cert profile

See [Section 10: Initial Setup Flow](#10-initial-setup-flow) for details.

### 22.8 Quick dev reset script

Save as `scripts/reset_dev.sh`:

```bash
#!/bin/bash
# Quick reset for local development
# Usage: ./scripts/reset_dev.sh
set -e

echo "=== PKI Dev Reset ==="
echo "WARNING: This destroys all local PKI data!"
read -p "Continue? (y/N) " confirm
[ "$confirm" = "y" ] || exit 1

PGPORT=${POSTGRES_PORT:-5434}

echo "1. Killing BEAM processes..."
pkill -9 -f "beam.smp" 2>/dev/null || true
sleep 2

echo "2. Dropping databases..."
for db in $(psql -h 127.0.0.1 -p $PGPORT -U postgres -t -c "SELECT datname FROM pg_database WHERE datname LIKE 'pki_%'" 2>/dev/null); do
  db=$(echo $db | xargs)
  [ -n "$db" ] && psql -h 127.0.0.1 -p $PGPORT -U postgres -c "DROP DATABASE \"$db\";" 2>/dev/null && echo "  Dropped $db"
done

echo "3. Creating databases..."
for db in pki_platform_dev pki_ca_engine_dev pki_ra_engine_dev pki_validation_dev; do
  psql -h 127.0.0.1 -p $PGPORT -U postgres -c "CREATE DATABASE $db;" 2>/dev/null && echo "  Created $db"
done

echo "4. Clearing SoftHSM2 tokens..."
rm -rf softhsm2/tokens/*/
softhsm2-util --init-token --free --label "PkiCA" --so-pin 12345678 --pin 1234 2>/dev/null && echo "  Token initialized"

echo "5. Running migrations..."
POSTGRES_PORT=$PGPORT
(cd src/pki_platform_engine && mix ecto.migrate --repo PkiPlatformEngine.PlatformRepo 2>&1 | tail -1)
(cd src/pki_ca_engine && mix ecto.migrate 2>&1 | tail -1)
(cd src/pki_ra_engine && mix ecto.migrate 2>&1 | tail -1)
(cd src/pki_validation && mix ecto.migrate 2>&1 | tail -1)

echo ""
echo "=== Reset complete ==="
echo "Start services and re-do initial setup (see deployment guide section 10)."
```

```bash
chmod +x scripts/reset_dev.sh
```
