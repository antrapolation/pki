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
   │   :4006     │    └─────┬──────┘    └─────┬──────┘  └────────────┘
   └─────┬───────┘          │                 │
         │            ┌─────▼──────┐    ┌─────▼──────┐
         │            │ CA Engine  │    │ RA Engine  │
         │            │   :4001    │◄───│   :4003    │
         │            └─────┬──────┘    └────────────┘
         │                  │
         │            ┌─────▼──────┐
         │            │  SoftHSM2  │  PKCS#11 (native)
         │            └────────────┘
         │
   ┌─────▼──────────────────────────────────────────┐
   │                PostgreSQL 17                     │
   │  pki_platform_dev    pki_tenant_{uuid} ...      │
   └─────────────────────────────────────────────────┘
```

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

### 3.1 Clone repository

```bash
cd /home/pki
git -c http.sslVerify=false clone https://vcs.antrapol.tech:3800/Incubator/pki.git
cd pki
git config http.sslVerify false
git submodule update --init --recursive
```

### 3.2 Environment file

```bash
cat > /home/pki/pki/.env << 'EOF'
# Database
POSTGRES_PORT=5432
POSTGRES_PASSWORD=<generated-strong-password>

# Secrets (generate with: openssl rand -base64 64)
SECRET_KEY_BASE=<generated-64-byte-secret>
INTERNAL_API_SECRET=<generated-32-byte-secret>

# Platform Portal
PLATFORM_ADMIN_USERNAME=<chosen-username>
PLATFORM_ADMIN_PASSWORD=<strong-password>
PLATFORM_PORTAL_URL=https://admin.straptrust.com

# Email (Resend API)
RESEND_API_KEY=<your-resend-api-key>
MAILER_FROM=PQC PKI Platform <noreply@straptrust.com>

# HSM
SOFTHSM2_CONF=/home/pki/softhsm2.conf

# Portal hostnames
CA_PORTAL_HOST=ca.straptrust.com
RA_PORTAL_HOST=ra.straptrust.com
PHX_HOST=straptrust.com

# Connection pool (pre-production)
POOL_SIZE=3
TENANT_POOL_SIZE=2

# Portals need this for localhost HTTP → set false only in dev
COOKIE_SECURE=true
EOF
```

Generate secrets:

```bash
openssl rand -base64 64   # SECRET_KEY_BASE
openssl rand -base64 32   # INTERNAL_API_SECRET
openssl rand -hex 4       # SoftHSM SO PIN
openssl rand -hex 4       # SoftHSM User PIN
```

### 3.3 Create databases

```bash
source /home/pki/pki/.env

sudo -u postgres psql << SQL
CREATE DATABASE pki_platform_dev;
CREATE DATABASE pki_ca_engine_dev;
CREATE DATABASE pki_ra_engine_dev;
CREATE DATABASE pki_validation_dev;
SQL
```

### 3.4 Fetch dependencies and compile

```bash
cd /home/pki/pki

# Fetch deps for all services
for dir in src/pki_platform_engine src/pki_ca_engine src/pki_ra_engine \
           src/pki_validation src/pki_audit_trail \
           src/pki_platform_portal src/pki_ca_portal src/pki_ra_portal; do
  echo "=== $dir ==="
  (cd $dir && mix deps.get && mix compile)
done
```

The PKCS#11 Rust NIF compiles automatically during `mix compile` of `strap_softhsm_priv_key_store_provider`.

### 3.5 Run migrations

```bash
source /home/pki/pki/.env

# Migration order matters
cd /home/pki/pki/src/pki_audit_trail && \
  CA_ENGINE_DB=pki_ca_engine_dev mix ecto.migrate

cd /home/pki/pki/src/pki_ca_engine && mix ecto.migrate

cd /home/pki/pki/src/pki_ra_engine && mix ecto.migrate

cd /home/pki/pki/src/pki_platform_engine && \
  mix ecto.migrate --repo PkiPlatformEngine.PlatformRepo

cd /home/pki/pki/src/pki_validation && mix ecto.migrate
```

---

## 4. Service Management (systemd)

Create systemd service files for each service so they start on boot and restart on failure.

### 4.1 Environment source file

```bash
cat > /home/pki/pki/env.sh << 'ENVEOF'
#!/bin/bash
set -a
source /home/pki/pki/.env
set +a
ENVEOF
chmod +x /home/pki/pki/env.sh
```

### 4.2 Platform Portal (port 4006 — starts tenant engines)

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
Environment=MIX_ENV=dev
Environment=PORT=4006
ExecStart=/bin/bash -lc 'source /home/pki/pki/env.sh && mix phx.server'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.3 CA Engine (port 4001)

```bash
sudo cat > /etc/systemd/system/pki-ca-engine.service << 'EOF'
[Unit]
Description=PQC PKI CA Engine
After=postgresql.service network.target
Requires=postgresql.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_ca_engine
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=dev
ExecStart=/bin/bash -lc 'source /home/pki/pki/env.sh && mix run --no-halt'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.4 RA Engine (port 4003)

```bash
sudo cat > /etc/systemd/system/pki-ra-engine.service << 'EOF'
[Unit]
Description=PQC PKI RA Engine
After=postgresql.service network.target
Requires=postgresql.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_ra_engine
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=dev
Environment=CA_ENGINE_URL=http://localhost:4001
ExecStart=/bin/bash -lc 'source /home/pki/pki/env.sh && mix run --no-halt'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.5 CA Portal (port 4002)

```bash
sudo cat > /etc/systemd/system/pki-ca-portal.service << 'EOF'
[Unit]
Description=PQC PKI CA Portal
After=pki-ca-engine.service
Requires=pki-ca-engine.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_ca_portal
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=dev
Environment=PORT=4002
Environment=CA_ENGINE_URL=http://localhost:4001
Environment=PLATFORM_DATABASE_URL=ecto://postgres:postgres@127.0.0.1:5432/pki_platform_dev
ExecStart=/bin/bash -lc 'source /home/pki/pki/env.sh && mix phx.server'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.6 RA Portal (port 4004)

```bash
sudo cat > /etc/systemd/system/pki-ra-portal.service << 'EOF'
[Unit]
Description=PQC PKI RA Portal
After=pki-ra-engine.service
Requires=pki-ra-engine.service

[Service]
Type=simple
User=pki
Group=pki
WorkingDirectory=/home/pki/pki/src/pki_ra_portal
EnvironmentFile=/home/pki/pki/.env
Environment=MIX_ENV=dev
Environment=PORT=4004
Environment=RA_ENGINE_URL=http://localhost:4003
Environment=PLATFORM_DATABASE_URL=ecto://postgres:postgres@127.0.0.1:5432/pki_platform_dev
ExecStart=/bin/bash -lc 'source /home/pki/pki/env.sh && mix phx.server'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 4.7 Enable and start all services

```bash
sudo systemctl daemon-reload

# Start order matters
sudo systemctl enable --now pki-platform-portal
sleep 5
sudo systemctl enable --now pki-ca-engine
sudo systemctl enable --now pki-ra-engine
sleep 3
sudo systemctl enable --now pki-ca-portal
sudo systemctl enable --now pki-ra-portal
```

### 4.8 Service management commands

```bash
# Check status
sudo systemctl status pki-platform-portal
sudo systemctl status pki-ca-engine

# View logs
sudo journalctl -u pki-platform-portal -f
sudo journalctl -u pki-ca-engine --since "5 minutes ago"

# Restart a service
sudo systemctl restart pki-ca-portal

# Restart all
sudo systemctl restart pki-platform-portal pki-ca-engine pki-ra-engine pki-ca-portal pki-ra-portal

# Stop all
sudo systemctl stop pki-ra-portal pki-ca-portal pki-ra-engine pki-ca-engine pki-platform-portal
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
| `api.straptrust.com` | RA Engine API (:4003) |
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

api.straptrust.com {
    reverse_proxy localhost:4003
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

### All Services

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY_BASE` | Yes | 64+ byte secret for session signing |
| `INTERNAL_API_SECRET` | Yes | Shared secret for service-to-service auth |
| `POSTGRES_PORT` | No | Default: 5432 |
| `SOFTHSM2_CONF` | Yes | Path to SoftHSM2 config file |
| `POOL_SIZE` | No | Default: 3 (DB connection pool per repo) |
| `TENANT_POOL_SIZE` | No | Default: 2 (DB pool per dynamic tenant repo) |

### Platform Portal (:4006)

| Variable | Required | Description |
|----------|----------|-------------|
| `PLATFORM_ADMIN_USERNAME` | Yes | Initial superadmin (first boot only) |
| `PLATFORM_ADMIN_PASSWORD` | Yes | Initial superadmin password |
| `RESEND_API_KEY` | No | Resend.com API key for emails |

### CA Portal (:4002)

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Default: 4002 |
| `CA_ENGINE_URL` | Yes | `http://localhost:4001` |
| `PLATFORM_DATABASE_URL` | Yes | `ecto://postgres:pass@127.0.0.1:5432/pki_platform_dev` |
| `COOKIE_SECURE` | No | `true` for HTTPS, `false` for localhost HTTP |
| `RESEND_API_KEY` | No | For user invitation emails |

### RA Portal (:4004)

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Default: 4004 |
| `RA_ENGINE_URL` | Yes | `http://localhost:4003` |
| `PLATFORM_DATABASE_URL` | Yes | Same as CA Portal |
| `COOKIE_SECURE` | No | Same as CA Portal |
| `RESEND_API_KEY` | No | For user invitation emails |

### CA Engine (:4001)

| Variable | Required | Description |
|----------|----------|-------------|
| No extra vars | — | Uses POSTGRES_PORT, INTERNAL_API_SECRET, SOFTHSM2_CONF |

### RA Engine (:4003)

| Variable | Required | Description |
|----------|----------|-------------|
| `CA_ENGINE_URL` | Yes | `http://localhost:4001` |

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
sudo -u postgres pg_dump pki_platform_dev | gzip > $BACKUP_DIR/pki_platform.sql.gz

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
2. Login with `PLATFORM_ADMIN_USERNAME` / `PLATFORM_ADMIN_PASSWORD`
3. This creates the initial admin (seeded from env vars, no email required)

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
# All engines
for port in 4001 4003 4005; do
  echo "Port $port: $(curl -s http://localhost:$port/health)"
done

# All portals
for port in 4002 4004 4006; do
  echo "Port $port: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:$port/login)"
done

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

# Recompile all services
for dir in src/pki_platform_engine src/pki_ca_engine src/pki_ra_engine \
           src/pki_validation src/pki_ca_portal src/pki_ra_portal \
           src/pki_platform_portal; do
  (cd $dir && mix deps.get && mix compile)
done

# Run migrations
cd src/pki_platform_engine && mix ecto.migrate --repo PkiPlatformEngine.PlatformRepo
cd ../pki_ca_engine && mix ecto.migrate
cd ../pki_ra_engine && mix ecto.migrate
cd ../pki_validation && mix ecto.migrate
cd ../..

# Restart services
sudo systemctl restart pki-platform-portal pki-ca-engine pki-ra-engine pki-ca-portal pki-ra-portal
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
sudo journalctl -u pki-ca-engine -n 50
# Common: missing deps → cd into service dir, run mix deps.get
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
| CA Engine | 1 core | 1 GB | Minimal |
| RA Engine | 1 core | 512 MB | Minimal |
| CA Portal | 1 core | 512 MB | Minimal |
| RA Portal | 1 core | 512 MB | Minimal |
| Validation | 0.5 core | 256 MB | Minimal |
| SoftHSM2 | — | — | Token files only |
| **Total** | ~8 cores | ~13 GB | ~20 GB initial |

Fits comfortably on the 8 vCPU / 24 GB / 400 GB server with headroom for 20-45 tenants.
