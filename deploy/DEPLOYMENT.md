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
┌────────────▼──────────────▼─────────────────┐
│  pki_portals (1 BEAM VM, +S 2:2)            │
│  CA Portal :4002 │ RA Portal :4004          │
│  Platform Portal :4006                       │
│  Engines loaded in-process (direct mode)     │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  pki_engines (1 BEAM VM, +S 4:4)            │
│  CA Engine API :4001 │ RA Engine API :4003  │
│  Validation :4005 │ Audit Trail              │
│  DB migrations, background jobs, tenants     │
└────────────┬────────────────────────────────┘
             │
┌────────────▼────────────────────────────────┐
│  pki_audit (1 BEAM VM, +S 1:1)              │
│  Lightweight audit trail service             │
└────────────┬────────────────────────────────┘
             │
    ┌────────▼───────────────────────────────────┐
    │ PostgreSQL :5432  │  SoftHSM2              │
    └────────────────────────────────────────────┘

3 BEAM VMs (down from 6) supervised by systemd
Schema-per-tenant: all tenants in shared DB using Ecto prefix:
```

---

## Table of Contents

1. [Server Requirements](#1-server-requirements)
2. [DNS Setup](#2-dns-setup)
3. [Secure the VPS](#3-secure-the-vps)
4. [Initial Server Setup](#4-initial-server-setup)
5. [Configure Environment](#5-configure-environment)
6. [Database & HSM Initialisation](#6-database--hsm-initialisation)
7. [Build Releases](#7-build-releases)
8. [Deploy Releases](#8-deploy-releases)
9. [Service Startup Order](#9-service-startup-order)
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
| `ca.straptrust.com` | A | `217.15.161.93` |
| `ra.straptrust.com` | A | `217.15.161.93` |
| `admin.straptrust.com` | A | `217.15.161.93` |

Verify propagation before continuing:
```bash
dig +short ca.straptrust.com
dig +short ra.straptrust.com
dig +short admin.straptrust.com
# All three should return 217.15.161.93
```

---

## 3. Secure the VPS

Run this **first** on a fresh server before installing anything. This is especially
important for a PKI/CA system that handles cryptographic keys.

### 3.1 Create a deploy user (from your local machine)

**Do not use root for day-to-day access.** Create a non-root user with sudo:

```bash
# SSH into the VPS as root (first and last time)
ssh root@217.15.161.93

# Create deploy user
adduser deploy
  usermod -aG sudo deploy

# Copy your SSH key to the deploy user
mkdir -p /home/deploy/.ssh
cp ~/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
chmod 600 /home/deploy/.ssh/authorized_keys

# Verify you can SSH as deploy (from another terminal!)
# ssh deploy@217.15.161.93
# Only proceed after confirming this works
```

### 3.2 Run VPS hardening script

```bash
# As the deploy user
ssh deploy@217.15.161.93
cd ~/pki

# Harden the VPS (runs as root via sudo)
sudo bash deploy/secure-vps.sh
```

Or with a custom SSH port:
```bash
sudo bash deploy/secure-vps.sh --ssh-port 2222
```

### 3.3 What `secure-vps.sh` does

| Layer | What | Detail |
|---|---|---|
| Firewall | UFW | Only SSH, HTTP (80), HTTPS (443) open — all other ports blocked |
| SSH | Key-only auth | Root login disabled, password auth disabled, max 3 attempts |
| Brute-force | Fail2ban | 3 failed SSH attempts → 1 hour IP ban |
| Network | sysctl hardening | SYN flood protection, no IP forwarding, no ICMP redirects, anti-spoofing |
| Kernel | ASLR + restrictions | Randomized memory layout, restricted ptrace/dmesg/kernel pointers |
| Memory | /dev/shm noexec | Prevents executable code in shared memory |
| Updates | Unattended upgrades | Nightly security patches (Erlang/PostgreSQL excluded from auto-update) |

### 3.4 After hardening

```bash
# Verify firewall
sudo ufw status

# Verify fail2ban
sudo fail2ban-client status sshd

# Verify SSH (from another terminal — don't disconnect yet!)
ssh deploy@217.15.161.93          # default port
ssh -p 2222 deploy@217.15.161.93  # if you changed SSH port
```

> **If locked out:** Use your VPS provider's web console to fix SSH config.

---

## 4. Initial Server Setup

Run once on the hardened server. This installs system packages, creates the
`pki` OS user, sets up directory structure, and auto-generates all secrets.

```bash
ssh deploy@217.15.161.93

# Clone the repo with submodules (Gitea self-hosted, SSL disabled for internal cert)
git clone -c http.sslVerify=false --recurse-submodules \
  https://vcs.antrapol.tech:3800/Incubator/pki.git ~/pki

# Persist the SSL skip for this repo only (so git pull works later)
cd ~/pki
git config http.sslVerify false

# If submodules were not cloned (e.g. cloned without --recurse-submodules)
# git submodule update --init --recursive

# Install everything
sudo bash deploy/install.sh
```

> **Note:** `http.sslVerify=false` is set per-repo only — it does not affect other
> git operations on the server. This is needed because the Gitea instance at
> `vcs.antrapol.tech:3800` uses a self-signed or internal TLS certificate.

What `install.sh` does:
- Runs **VPS hardening** if not already done (calls `secure-vps.sh`)
- Installs **Erlang/OTP + Elixir**, **PostgreSQL**, **SoftHSM2**, **Caddy**, **argon2**
- Creates OS user `pki` with home at `/opt/pki`
- Creates `/opt/pki/releases/{engines,portals,audit}` directories
- Generates a unique Erlang cookie per release in `/opt/pki/.cookies/` (mode 400)
- Writes `/etc/softhsm2.conf` with token directory `/var/lib/softhsm/tokens/`
- Copies `Caddyfile` to `/etc/caddy/Caddyfile`
- Installs 3 systemd `.service` files to `/etc/systemd/system/`
- **Auto-generates `/opt/pki/.env`** with all passwords, salts, and keys (via `generate-env.sh`)

---

## 5. Configure Environment

`install.sh` automatically generates `/opt/pki/.env` with fresh cryptographic
secrets using `deploy/generate-env.sh`. All passwords, salts, keys, and the admin
password hash are generated automatically.

### 4.1 Review the generated .env

```bash
sudo cat /opt/pki/.env
```

Everything is pre-filled except:
- **RESEND_API_KEY** — set this to your Resend API key for email delivery
- **Portal hostnames** — defaults to `ca.straptrust.com` etc; change if needed

### 4.2 (Optional) Regenerate interactively

If you need to customise hostnames, admin username, or provide your own admin password:

```bash
sudo bash deploy/generate-env.sh --force --interactive
```

This prompts for each configurable value while still auto-generating all secrets.

### 4.3 What gets generated

| Variable | How it's generated |
|---|---|
| `POSTGRES_PASSWORD` | `openssl rand -base64 18` |
| `SECRET_KEY_BASE` | `openssl rand -base64 64` |
| `INTERNAL_API_SECRET` | `openssl rand -base64 32` |
| `*_SIGNING_SALT` (×3) | `openssl rand -base64 16` |
| `*_ENCRYPTION_SALT` (×3) | `openssl rand -base64 16` |
| `SOFTHSM_SO_PIN` | `openssl rand -hex 4` |
| `SOFTHSM_USER_PIN` | `openssl rand -hex 4` |
| `PLATFORM_ADMIN_PASSWORD_HASH` | Random password → `argon2` hash |
| `DATABASE_URL` (×5) | Derived from generated `POSTGRES_PASSWORD` |

The admin password is displayed once during generation — save it.

### 4.4 Manual password hash generation

If you need to change the admin password later:

```bash
# Using argon2 CLI (installed by install.sh)
echo -n "new_password" | argon2 $(openssl rand -hex 8) -id -t 3 -m 16 -p 4 -l 32 -e

# Or using the portals release
/opt/pki/releases/portals/bin/pki_portals eval \
  'IO.puts Argon2.hash_pwd_salt("new_password")'
```

Then update `/opt/pki/.env` and restart portals:
```bash
sudo systemctl restart pki-portals
```

---

## 6. Database & HSM Initialisation

Database creation, SoftHSM2 token initialisation, and Caddy startup are all handled
automatically by `deploy.sh setup` (Section 8). You can skip to Section 7 (Build).

If you prefer to do it manually:

<details>
<summary>Manual database creation</summary>

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
```
</details>

<details>
<summary>Manual SoftHSM2 token initialisation</summary>

```bash
source /opt/pki/.env

sudo -u pki softhsm2-util \
  --init-token \
  --free \
  --label "$SOFTHSM_TOKEN_LABEL" \
  --so-pin  "$SOFTHSM_SO_PIN" \
  --pin     "$SOFTHSM_USER_PIN"

# Verify: should show Token Label: PkiCA, Initialized: yes
sudo -u pki softhsm2-util --show-slots
```
</details>

> **Note:** If you ever re-initialise the SoftHSM2 token, all keys stored in it are
> permanently destroyed. Back up `/var/lib/softhsm/tokens/` regularly.

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
├── pki_engines-0.2.0.tar.gz
├── pki_portals-0.2.0.tar.gz
└── pki_audit-0.2.0.tar.gz
```

### Copy tarballs to server

```bash
# From build machine
scp deploy/releases/*.tar.gz deploy@217.15.161.93:~/pki/deploy/releases/
```

---

## 8. Deploy Releases

Run on the server as root.

### First-time deployment (recommended)

`setup` creates databases, initialises SoftHSM2, deploys all releases, runs
migrations, and starts Caddy — one command:

```bash
cd ~/pki
sudo bash deploy/deploy.sh setup
```

### Subsequent deployments

```bash
cd ~/pki
sudo bash deploy/deploy.sh          # deploy all (creates DBs if missing, restarts Caddy)
sudo bash deploy/deploy.sh engines   # deploy only engines
sudo bash deploy/deploy.sh portals   # deploy only portals
```

Expected output:
```
[deploy] Ensuring PostgreSQL databases exist...
[deploy]   ✓ pki_ca_engine exists
[deploy]   ✓ pki_ra_engine exists
[deploy]   ✓ pki_validation exists
[deploy]   ✓ pki_audit_trail exists
[deploy]   ✓ pki_platform exists
[deploy] Deploying engines from pki_engines-0.2.0.tar.gz...
[deploy]   Extracted to /opt/pki/releases/engines
[deploy]   Running migrations for engines...
[deploy]   Started pki-engines
[deploy]   ✓ pki-engines is running
[deploy] Deploying portals from pki_portals-0.2.0.tar.gz...
[deploy]   Started pki-portals
[deploy]   ✓ pki-portals is running
[deploy] Deploying audit from pki_audit-0.2.0.tar.gz...
[deploy]   Started pki-audit
[deploy]   ✓ pki-audit is running
[deploy] Starting Caddy (TLS termination)...
[deploy]   ✓ Caddy is running
[deploy] All services deployed.
```

---

## 9. Service Startup Order

After deployment, all services are enabled and started automatically by systemd.
On server reboot, systemd starts everything in dependency order:

```
postgresql       (system)
  └── pki-engines    (After=postgresql — runs CA/RA/Validation APIs + migrations)
  └── pki-portals    (After=postgresql — runs CA/RA/Platform portals in direct mode)
  └── pki-audit      (After=postgresql — lightweight audit trail service)
caddy                (TLS termination in front of portals)
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
# Follow logs for a release
journalctl -u pki-engines -f

# Last 100 lines
journalctl -u pki-engines -n 100

# All PKI services since last boot
journalctl -u 'pki-*' -b

# Filter by time
journalctl -u pki-engines --since "2026-03-29 10:00" --until "2026-03-29 11:00"
```

### Service control

```bash
# Status
systemctl status pki-engines

# Restart a service (e.g. after config change)
systemctl restart pki-engines

# Stop / Start
systemctl stop pki-engines
systemctl start pki-engines
```

### BEAM remote shell

Connect a live IEx shell to a running BEAM VM — no restart needed:

```bash
# Connect to engines release
sudo -u pki /opt/pki/releases/engines/bin/pki_engines remote

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

Or directly via the engines release:
```bash
sudo -u pki env $(grep -v '^#' /opt/pki/.env | xargs) \
  /opt/pki/releases/engines/bin/pki_engines eval \
  "PkiSystem.Release.migrate()"
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
sudo -u pki /opt/pki/releases/engines/bin/pki_engines remote << 'IEX'
:erlang.system_info(:process_count) |> IO.inspect(label: "processes")
:erlang.memory() |> IO.inspect(label: "memory bytes")
IEX
```

---

## 12. Upgrading

For **zero-downtime upgrades** (building on server):

```bash
ssh deploy@217.15.161.93
cd ~/pki
git pull --recurse-submodules   # sslVerify already disabled per-repo
source /opt/pki/.env
bash deploy/build.sh
sudo bash deploy/deploy.sh  # or: sudo bash deploy/deploy.sh engines
```

`deploy.sh` will:
1. Back up the current release to `engines.bak`
2. Stop the service (graceful OTP shutdown — in-flight requests finish)
3. Extract the new release
4. Run any new migrations (engines only)
5. Start the new version
6. Report health status

If something goes wrong:
```bash
sudo bash ~/pki/deploy/deploy.sh rollback engines
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
journalctl -u pki-engines -n 50 --no-pager

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
# Check per-release memory
systemctl status 'pki-*' | grep -E 'Memory|pki-'

# If a VM is using too much, reduce pool_size in .env:
POOL_SIZE=5   # default is 10 DB connections per VM

# Then restart that release
systemctl restart pki-engines
```

### BEAM scheduler saturation

```bash
# Check CPU usage per VM (now only 3 VMs)
top -p $(pgrep -d',' beam.smp)

# Tune scheduler limits per release in systemd service files:
# Edit /etc/systemd/system/pki-engines.service:
#   Environment=ELIXIR_ERL_OPTIONS=+S 2:2 +SDcpu 2
# Then: systemctl daemon-reload && systemctl restart pki-engines
```

---

## Summary: Full Deployment Checklist

```
── Server prep ──
[ ] DNS A records created and propagated
[ ] Create deploy user on VPS (not root!)
[ ] git clone repo to ~/pki on server
[ ] sudo bash deploy/secure-vps.sh        ← firewall, SSH hardening, fail2ban
[ ] Verify SSH works from a second terminal before disconnecting

── Install & configure ──
[ ] sudo bash deploy/install.sh           ← packages, .env with auto-generated secrets
[ ] Save the admin password printed during install
[ ] (Optional) Set RESEND_API_KEY in /opt/pki/.env
[ ] (Optional) Change portal hostnames if using staging domains

── Build & deploy ──
[ ] source /opt/pki/.env && bash deploy/build.sh
[ ] sudo bash deploy/deploy.sh setup      ← DBs, HSM, deploy, Caddy

── Verify ──
[ ] curl https://ca.straptrust.com/health  → {"status":"ok"}
[ ] https://ca.straptrust.com/setup  — create first CA admin
[ ] https://ra.straptrust.com/setup  — create first RA admin
[ ] https://admin.straptrust.com    — log in as trust_admin

── CA setup ──
[ ] Configure keystore in CA Portal
[ ] Run key ceremony
[ ] Create issuer keys
```
