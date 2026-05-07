# PKI CA System — Production Deployment Guide
## BEAM Direct Deployment (No Containers)

All PKI services run as native Elixir/OTP releases supervised by systemd.
Caddy handles TLS termination and dynamically updates its routing as tenants
are provisioned. PostgreSQL and SoftHSM2 run as system services.

---

## Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  Caddy  (ports 80 / 443)                                     │
│                                                              │
│  admin.<domain>             → localhost:4006                 │
│  <slug>.ca.<domain>         → localhost:<tenant-port>  ┐     │
│  <slug>.ra.<domain>         → localhost:<tenant-port>  ├─ dynamic,│
│  <slug>.ocsp.<domain>       → localhost:<tenant-port>  ┘ via API  │
└──────────────────────────────────────────────────────────────┘
         │                            │
         ▼                            ▼
┌──────────────────┐      ┌───────────────────────────────────┐
│  pki_platform    │      │  pki_tenant_node (one per tenant) │
│  port 4006       │      │  port 5001–5999  (PortAllocator)  │
│                  │      │                                   │
│  Platform admin  │      │  CA engine     (in-process)       │
│  portal          │      │  RA engine     (in-process)       │
│  Tenant lifecycle│      │  pki_validation OCSP/CRL          │
│  CaddyConfigurator│     │  pki_tenant_web portal UI         │
│  PortAllocator   │      │  Mnesia disc_copies               │
└──────────────────┘      └───────────────────────────────────┘
         │
         ├── pki_engines  (audit-trail receiver, platform bootstrap)
         └── pki_audit    (lightweight audit trail)
                │
       ┌────────▼────────────────────┐
       │ PostgreSQL :5432             │
       │ pki_platform DB only         │
       │ (tenant data lives in Mnesia)│
       └──────────────────────────────┘
```

**Key points:**

- Tenant CA/RA/Validation data lives in **Mnesia** on each tenant BEAM node —
  PostgreSQL is only used by the platform node and audit service.
- CA and RA engines are **in-process** — no HTTP API between them and the portals.
- When a tenant is provisioned, `pki_platform` allocates a port (5001–5999),
  starts a `pki_tenant_node` BEAM, and calls the Caddy admin API to add a
  reverse-proxy route. Deprovisioning removes the route automatically.
- UFW only exposes ports 80 and 443. All tenant ports are localhost-only.

---

## Table of Contents

1. [Server Requirements](#1-server-requirements)
2. [DNS Setup](#2-dns-setup)
3. [VPS Setup — One Time](#3-vps-setup--one-time)
4. [Configure Environment](#4-configure-environment)
5. [Build Releases (on VPS)](#5-build-releases-on-vps)
6. [Deploy](#6-deploy)
7. [Service Startup Order](#7-service-startup-order)
8. [Verify Deployment](#8-verify-deployment)
9. [Provisioning Tenants](#9-provisioning-tenants)
10. [Operations Reference](#10-operations-reference)
11. [Upgrading](#11-upgrading)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Server Requirements

| Resource | Minimum | Target (current VPS) |
|---|---|---|
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| CPU | 2 vCPU | 8 vCPU |
| RAM | 4 GB | 24 GB |
| Disk | 40 GB SSD | 400 GB SSD |
| Network | Public IP | Public IP |

**Tenant capacity on 8 vCPU / 24 GB:** ~25–30 idle tenants; ~10–12 tenants
under active signing load before a second VPS is warranted.

---

## 2. DNS Setup

You need **four sets of DNS A records** all pointing to the VPS public IP.
Caddy uses them to obtain Let's Encrypt TLS certificates automatically.

| Record | Type | Example |
|---|---|---|
| `admin.straptrust.com` | A | `<VPS_IP>` |
| `*.ca.straptrust.com` | A | `<VPS_IP>` |
| `*.ra.straptrust.com` | A | `<VPS_IP>` |
| `*.ocsp.straptrust.com` | A | `<VPS_IP>` |

> The wildcard records cover all tenants — when `acme-corp` is provisioned,
> `acme-corp.ca.straptrust.com`, `acme-corp.ra.straptrust.com`, and
> `acme-corp.ocsp.straptrust.com` resolve automatically.

Verify propagation before continuing:

```bash
dig +short admin.straptrust.com
dig +short test.ca.straptrust.com   # wildcard test
# Both should return <VPS_IP>
```

---

## 3. VPS Setup — One Time

### 3.1 Create a non-root deploy user

SSH in as root for the first and last time:

```bash
ssh root@<VPS_IP>

adduser deploy
usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh
cp ~/.ssh/authorized_keys /home/deploy/.ssh/
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys
```

Open a second terminal and verify `ssh deploy@<VPS_IP>` works **before disconnecting root**.

### 3.2 Clone the repository

```bash
ssh deploy@<VPS_IP>

git clone -c http.sslVerify=false --recurse-submodules \
  https://vcs.antrapol.tech:3800/Incubator/pki.git ~/pki

cd ~/pki
git config http.sslVerify false   # persists for future git pulls on this repo
```

### 3.3 Harden the VPS

```bash
sudo bash deploy/secure-vps.sh
# Custom SSH port (optional):
sudo bash deploy/secure-vps.sh --ssh-port 2222
```

What it does (9 steps):

| Step | What |
|---|---|
| 1 | System package updates |
| 2 | Install ufw, fail2ban, unattended-upgrades |
| 3 | UFW firewall — SSH, HTTP :80, HTTPS :443 only |
| 4 | SSH hardening — key-only auth, no root login |
| 5 | Fail2ban — 3 failures → 1 hour IP ban |
| 6 | Kernel sysctl — ASLR, SYN protection, BEAM tuning (`vm.swappiness=1`, `fs.file-max=2M`, large socket buffers) |
| 7 | Transparent Huge Pages disabled — BEAM allocator incompatible with 2 MB THP pages |
| 8 | `/dev/shm` mounted `noexec,nosuid,nodev` |
| 9 | Unattended security upgrades (Erlang/PostgreSQL excluded) |

After hardening, verify:

```bash
sudo ufw status
sudo fail2ban-client status sshd
# From a second terminal — confirm you can still SSH in
```

> **Locked out?** Use your VPS provider's web console to fix SSH config.

### 3.4 Install system packages and services

```bash
sudo bash deploy/install.sh
```

What it does:

- Runs VPS hardening if not already done
- Creates `pki` OS user with home at `/opt/pki`
- Creates `/opt/pki/releases/{platform,engines,tenant,audit}/` directories
- Creates `/var/lib/pki/mnesia/{platform,engines,audit}/` directories
- Installs: Erlang/OTP, Elixir 1.18, PostgreSQL, SoftHSM2, Caddy, Rust, liboqs, argon2
- Generates Erlang cookies in `/opt/pki/.cookies/` (mode 400)
- Writes `/etc/softhsm2.conf`
- Copies `Caddyfile` to `/etc/caddy/Caddyfile`
- Installs all systemd `.service` files (including `pki-tenant@.service` template)
- **Auto-generates `/opt/pki/.env`** with all passwords, salts, and keys
- Tunes PostgreSQL: `shared_buffers=25% RAM`, `effective_cache_size=75% RAM`,
  `work_mem=16 MB`, `max_connections=500`

**Save the admin password printed at the end.**

---

## 4. Configure Environment

`install.sh` auto-generates `/opt/pki/.env`. The only things you need to set manually:

```bash
sudo nano /opt/pki/.env
```

| Variable | Required | Description |
|---|---|---|
| `PLATFORM_HOST` | Yes | `admin.straptrust.com` |
| `BASE_DOMAIN` | Yes | `straptrust.com` (used for tenant subdomains) |
| `CADDY_ACME_EMAIL` | Yes | Email for Let's Encrypt registration |
| `RESEND_API_KEY` | No | Email delivery (optional for initial setup) |

Everything else (passwords, salts, secret keys, HSM PINs) is auto-generated.

### Optional: regenerate interactively

```bash
sudo bash deploy/generate-env.sh --force --interactive
```

### Change admin password later

```bash
echo -n "new_password" | argon2 $(openssl rand -hex 8) -id -t 3 -m 16 -p 4 -l 32 -e
# Paste the output into /opt/pki/.env as PLATFORM_ADMIN_PASSWORD_HASH
sudo systemctl restart pki-platform
```

---

## 5. Build Releases (on VPS)

Building directly on the VPS is the recommended approach — `install.sh` already
provides all build dependencies (Erlang/OTP, Elixir, Rust, liboqs, cmake).

```bash
cd ~/pki
source /opt/pki/.env
bash deploy/build.sh
```

**First build takes ~10 minutes** — Rust NIFs (liboqs, SoftHSM2 Rustler) compile
from source. Subsequent builds use the cached deps and take ~2 minutes.

Output tarballs in `deploy/releases/`:

```
pki_platform-<vsn>.tar.gz       Platform admin portal + tenant lifecycle
pki_engines-<vsn>.tar.gz        Audit trail receiver + platform bootstrap
pki_tenant_node-<vsn>.tar.gz    Per-tenant CA/RA/Validation (deployed on-demand)
pki_audit-<vsn>.tar.gz          Lightweight audit trail service
pki_replica-<vsn>.tar.gz        Multi-host warm standby (optional)
```

### Alternatively: build on a separate machine

If you prefer not to build on the server:

```bash
# On build machine — same OS/Erlang version as the server
source /path/to/.env && bash deploy/build.sh
scp deploy/releases/*.tar.gz deploy@<VPS_IP>:~/pki/deploy/releases/
```

---

## 6. Deploy

### First-time setup (recommended)

One command — creates the database, initialises SoftHSM2, deploys all releases,
and starts Caddy:

```bash
cd ~/pki
sudo bash deploy/deploy.sh setup
```

Expected output:

```
[deploy] === First-run setup ===
[deploy] Checking PostgreSQL max_connections... ✓ max_connections = 500
[deploy] Ensuring PostgreSQL databases exist...
[deploy]   ✓ pki_platform exists
[deploy] Initialising SoftHSM2 token...
[deploy]   ✓ Token initialised
[deploy] Deploying engines ...
[deploy]   ✓ pki-engines is running
[deploy] Deploying platform ...
[deploy]   ✓ pki-platform is running
[deploy] Deploying audit ...
[deploy]   ✓ pki-audit is running
[deploy] Starting Caddy...
[deploy]   ✓ Caddy is running
[deploy] === Setup complete ===
```

### Subsequent deployments / upgrades

```bash
sudo bash deploy/deploy.sh            # redeploy all three services
sudo bash deploy/deploy.sh platform   # platform only
sudo bash deploy/deploy.sh engines    # engines only
sudo bash deploy/deploy.sh audit      # audit only
sudo bash deploy/deploy.sh migrate    # run DB migrations only
```

### Rollback

```bash
sudo bash deploy/deploy.sh rollback platform
```

---

## 7. Service Startup Order

systemd handles dependency ordering on reboot:

```
postgresql
  └── pki-engines    (Requires=postgresql)
  └── pki-audit      (Requires=postgresql)
  └── pki-platform   (After=postgresql, pki-engines)
        └── pki-tenant@<id>  (Wants=pki-platform — survives platform restart)
caddy
```

Check all services:

```bash
systemctl status 'pki-*' caddy postgresql
sudo bash deploy/deploy.sh status
```

---

## 8. Verify Deployment

### Service health

```bash
# Platform admin portal
curl -s http://localhost:4006/health
# Expected: {"status":"ok"} or HTTP 200

# Platform admin portal via Caddy (TLS)
curl -sI https://admin.straptrust.com
# Expected: HTTP/2 200
```

### TLS certificates

```bash
echo | openssl s_client -connect admin.straptrust.com:443 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
# Issuer should be Let's Encrypt
```

### Caddy dynamic routing (after first tenant is provisioned)

```bash
# Check Caddy's live config — should show route-<slug> entries
curl -s http://localhost:2019/config/apps/http/servers/srv0/routes | jq .
```

### Platform admin first login

Open `https://admin.straptrust.com` and log in with:
- Username: value of `PLATFORM_ADMIN_USERNAME` in `/opt/pki/.env`
- Password: printed during `install.sh` (or check `PLATFORM_ADMIN_PASSWORD` in `.env`)

---

## 9. Provisioning Tenants

Tenants are provisioned through the platform admin portal at
`https://admin.straptrust.com`. The platform:

1. Allocates a port from the pool (5001–5999)
2. Starts a `pki_tenant_node` BEAM (registered as `pki_tenant_<slug>@127.0.0.1`)
3. Creates `/var/lib/pki/mnesia/tenant-<id>/` for Mnesia disc_copies
4. Calls the Caddy admin API to add routes for:
   - `<slug>.ca.straptrust.com → localhost:<port>`
   - `<slug>.ra.straptrust.com → localhost:<port>`
   - `<slug>.ocsp.straptrust.com → localhost:<port>`

No manual Caddyfile edits are needed — routing is fully automatic.

### Persistent tenant nodes (systemd-managed)

By default, tenant BEAM nodes are spawned by `:peer` from `pki_platform`.
For tenants that should survive a platform restart, enable their systemd unit:

```bash
# Enable and start a tenant's BEAM as a standalone systemd service
sudo systemctl enable --now pki-tenant@<tenant-slug>.service

# Logs
journalctl -u pki-tenant@acme-corp -f

# Restart
sudo systemctl restart pki-tenant@acme-corp

# Status of all tenant nodes
systemctl status 'pki-tenant@*'
```

### After provisioning — run the key ceremony

Access the tenant's CA portal at `https://<slug>.ca.straptrust.com`:

1. Log in as `ca_admin`
2. Configure a keystore (SoftHSM2 local or external PKCS#11 HSM)
3. Run the key ceremony to generate root CA keys
4. Create issuer keys

---

## 10. Operations Reference

### Logs

```bash
journalctl -u pki-platform -f
journalctl -u pki-engines -f
journalctl -u pki-audit -f
journalctl -u pki-tenant@acme-corp -f

# All PKI services since last boot
journalctl -u 'pki-*' -b

# Filter by time
journalctl -u pki-platform --since "2026-05-07 10:00" --until "2026-05-07 11:00"
```

### Service control

```bash
systemctl restart pki-platform
systemctl restart pki-engines
systemctl restart pki-audit
systemctl restart pki-tenant@acme-corp

# Stop without restart
systemctl stop pki-tenant@acme-corp
```

### Live IEx shell (no restart required)

```bash
sudo -u pki /opt/pki/releases/platform/bin/pki_platform remote
sudo -u pki /opt/pki/releases/engines/bin/pki_engines remote
sudo -u pki /opt/pki/releases/audit/bin/pki_audit remote
```

> **Warning:** `System.halt()` in the remote shell kills the BEAM process.
> Use `:q` or `Ctrl+C` to disconnect safely.

### Useful IEx commands

```elixir
# Connected tenant nodes
Node.list()

# BEAM memory breakdown
:erlang.memory()

# Process count
:erlang.system_info(:process_count)

# Scheduler utilisation (1-second sample)
:scheduler.utilization(1000)

# Mnesia info
:mnesia.system_info(:tables)
:mnesia.table_info(:issued_certificates, :size)

# Terminal BEAM dashboard (no X11 needed)
:observer_cli.start()
```

### Port allocation

```bash
# See which tenants have which ports allocated
sudo -u pki /opt/pki/releases/platform/bin/pki_platform remote
iex> PkiPlatformEngine.PortAllocator.list_assignments()
```

### Check Caddy live routes

```bash
curl -s http://localhost:2019/config/apps/http/servers/srv0/routes | jq '[.[] | {"id": .["@id"], "hosts": .match[0].host, "upstream": .handle[0].upstreams[0].dial}]'
```

### Database

```bash
# Connect to PostgreSQL
sudo -u postgres psql pki_platform

# Connection count
sudo -u postgres psql -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"

# Run migrations manually
sudo bash ~/pki/deploy/deploy.sh migrate
```

### SoftHSM2

```bash
# Check token status
sudo -u pki softhsm2-util --show-slots

# If token shows "Not initialized":
source /opt/pki/.env
sudo -u pki softhsm2-util --init-token --free \
  --label "$SOFTHSM_TOKEN_LABEL" \
  --so-pin "$SOFTHSM_SO_PIN" \
  --pin "$SOFTHSM_USER_PIN"
```

---

## 11. Upgrading

```bash
ssh deploy@<VPS_IP>
cd ~/pki

# Pull latest code
git pull --recurse-submodules

# Build new releases on the VPS
source /opt/pki/.env
bash deploy/build.sh

# Deploy (stops → migrates → starts for each service)
sudo bash deploy/deploy.sh
```

`deploy.sh` backs up the current release to `<service>.bak` before swapping,
so rollback is always available:

```bash
sudo bash deploy/deploy.sh rollback platform
sudo bash deploy/deploy.sh rollback engines
```

**Tenant nodes** are not redeployed by `deploy.sh` — restart them individually
or let `pki_platform` manage their lifecycle via `:peer`.

```bash
# After a pki_tenant_node tarball update, replace the release and restart
sudo bash deploy/deploy.sh tenant  # if deploy.sh supports it, else manual:
sudo -u pki tar -xzf ~/pki/deploy/releases/pki_tenant_node-<vsn>.tar.gz \
  -C /opt/pki/releases/tenant
sudo systemctl restart 'pki-tenant@*'
```

---

## 12. Troubleshooting

### Service fails to start

```bash
journalctl -u pki-platform -n 50 --no-pager

# Common causes:
# 1. .env variable missing or wrong value
# 2. PostgreSQL not running
# 3. Port already in use (check with: ss -tlnp | grep 4006)
# 4. Release binary missing (check: ls /opt/pki/releases/platform/bin/)

sudo -u pki cat /opt/pki/.env | head -5   # check .env readable by pki user
```

### Database connection error

```bash
systemctl status postgresql
ss -tlnp | grep 5432
sudo -u postgres psql pki_platform -c '\l'
```

### Caddy not issuing TLS certificates

```bash
journalctl -u caddy -n 50

# Checklist:
# 1. DNS propagated?  dig +short admin.straptrust.com
# 2. Port 80 open?    ufw status
# 3. CADDY_ACME_EMAIL set in /opt/pki/.env?
# 4. Caddy admin API enabled? (check /etc/caddy/Caddyfile — must not have 'admin off')

curl -v http://admin.straptrust.com/.well-known/acme-challenge/test
```

### Caddy admin API unreachable (tenant routes not adding)

```bash
curl -s http://localhost:2019/config/ | jq .
# If this fails, Caddy's admin API is disabled or Caddy is not running.
# Check /etc/caddy/Caddyfile — must have 'admin localhost:2019' not 'admin off'
systemctl restart caddy
```

### Tenant BEAM not starting

```bash
journalctl -u pki-tenant@acme-corp -n 50 --no-pager

# Check if port is in use
ss -tlnp | grep 500

# Check Mnesia directory exists and is owned by pki
ls -la /var/lib/pki/mnesia/tenant-<id>
# If missing: sudo mkdir -p /var/lib/pki/mnesia/tenant-<id> && sudo chown pki:pki /var/lib/pki/mnesia/tenant-<id>
```

### High memory on a tenant node

```bash
systemctl status 'pki-tenant@*' | grep Memory

# Connect and inspect
sudo -u pki /opt/pki/releases/tenant/bin/pki_tenant_node remote
iex> :erlang.memory()
iex> :mnesia.table_info(:issued_certificates, :memory)
```

### OOM killer hit a service

```bash
journalctl -k | grep -i oom
dmesg | grep -i "out of memory"

# Check OOMScoreAdjust is applied (lower = more protected):
cat /proc/$(pgrep -f pki_platform | head -1)/oom_score
# Should be well below 0 given OOMScoreAdjust=-500 in pki-platform.service
```

### BEAM scheduler saturation

```bash
# CPU per process
top -p $(pgrep -d',' beam.smp)

# From IEx
iex> :scheduler.utilization(1000)

# Reduce dirty-CPU schedulers if PQC NIFs are saturating:
# Edit /etc/systemd/system/pki-tenant@.service
# Change: +SDcpu 2:2  →  +SDcpu 1:1
# Then:
sudo systemctl daemon-reload
sudo systemctl restart 'pki-tenant@*'
```

---

## Full Deployment Checklist

```
── Prerequisites ──────────────────────────────────────────────
[ ] DNS A records created and propagated (admin.*, *.ca.*, *.ra.*, *.ocsp.*)
[ ] Create deploy user on VPS (NOT root)

── Server setup ───────────────────────────────────────────────
[ ] git clone repo to ~/pki on VPS (with --recurse-submodules)
[ ] sudo bash deploy/secure-vps.sh        ← firewall, SSH, sysctl, THP
[ ] Verify SSH still works from a second terminal
[ ] sudo bash deploy/install.sh           ← all packages, .env generated
[ ] Save the admin password printed during install

── Configure ──────────────────────────────────────────────────
[ ] sudo nano /opt/pki/.env
      PLATFORM_HOST=admin.straptrust.com
      BASE_DOMAIN=straptrust.com
      CADDY_ACME_EMAIL=you@example.com
      RESEND_API_KEY=re_xxxx  (optional)

── Build ──────────────────────────────────────────────────────
[ ] source /opt/pki/.env && bash deploy/build.sh   ← ~10 min first run

── Deploy ─────────────────────────────────────────────────────
[ ] sudo bash deploy/deploy.sh setup

── Verify ─────────────────────────────────────────────────────
[ ] systemctl status 'pki-*' caddy postgresql   ← all active
[ ] curl -sI https://admin.straptrust.com       ← HTTP/2 200
[ ] Log in at https://admin.straptrust.com

── Provision first tenant ─────────────────────────────────────
[ ] Create tenant via platform admin portal
[ ] Verify routing: curl -sI https://<slug>.ca.straptrust.com
[ ] Run key ceremony in CA portal
[ ] Create issuer keys
```
