#!/usr/bin/env bash
# deploy/install.sh — One-time server setup for PKI CA System (BEAM direct deployment)
#
# Run as root on a fresh Ubuntu 22.04 / Debian 12 server:
#   sudo bash deploy/install.sh
#
# What this does:
#   1. Creates the 'pki' OS user
#   2. Sets up /opt/pki/ directory structure
#   3. Installs system packages (Erlang/OTP via apt, Elixir 1.18 via GitHub, PostgreSQL, SoftHSM2, Caddy)
#   4. Generates per-service Erlang cookies
#   5. Configures SoftHSM2 token directory permissions
#   6. Enables and starts PostgreSQL

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[install]${NC} $*"; }
warn()    { echo -e "${YELLOW}[install]${NC} $*"; }
die()     { echo -e "${RED}[install] ERROR:${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash deploy/install.sh"

# ── 0. VPS hardening (skip if already done) ─────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f /etc/sysctl.d/99-pki-hardening.conf ]]; then
  info "Running VPS security hardening..."
  bash "${SCRIPT_DIR}/secure-vps.sh"
else
  info "VPS already hardened (sysctl conf exists), skipping."
fi

# ── 1. Create pki user ───────────────────────────────────────────────────────
if ! id pki &>/dev/null; then
  info "Creating 'pki' system user..."
  useradd --system --shell /bin/bash --home /opt/pki --create-home pki
else
  info "'pki' user already exists, skipping."
fi

# ── 2. Directory structure ───────────────────────────────────────────────────
info "Creating /opt/pki directory structure..."
mkdir -p /opt/pki/{releases/{platform,engines,tenant,audit},.cookies,logs}
chown -R pki:pki /opt/pki
chmod 750 /opt/pki/.cookies

# Mnesia disc_copies directories — one per static BEAM node.
# Tenant node directories (tenant-<id>) are created by the provisioner at runtime.
info "Creating Mnesia data directories..."
mkdir -p /var/lib/pki/mnesia/{platform,engines,audit}
chown -R pki:pki /var/lib/pki
chmod 750 /var/lib/pki/mnesia

# ── 3. System packages ───────────────────────────────────────────────────────
info "Installing system packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  curl ca-certificates gnupg wget unzip \
  build-essential cmake ninja-build \
  erlang-nox erlang-dev erlang-public-key erlang-ssl erlang-crypto erlang-asn1 \
  postgresql postgresql-client \
  softhsm2 \
  argon2 \
  libssl-dev

# Rust toolchain (needed by strap_softhsm_priv_key_store_provider NIF via Rustler)
if ! command -v cargo &>/dev/null; then
  info "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  info "Rust $(rustc --version) installed"
else
  info "Rust already installed ($(rustc --version)), skipping."
fi

# liboqs (Post-Quantum Cryptography library — needed by pki_oqs_nif)
if [[ ! -f /usr/local/include/oqs/oqs.h ]]; then
  info "Building liboqs from source..."
  LIBOQS_TMP=$(mktemp -d)
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_TMP/liboqs"
  mkdir -p "$LIBOQS_TMP/liboqs/build"
  cd "$LIBOQS_TMP/liboqs/build"
  cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=OFF .. >/dev/null 2>&1
  ninja >/dev/null 2>&1
  ninja install >/dev/null 2>&1
  cd /
  rm -rf "$LIBOQS_TMP"
  info "liboqs installed to /usr/local"
else
  info "liboqs already installed, skipping."
fi

# Elixir 1.18.x from GitHub releases (Ubuntu 24.04 ships Elixir 1.14 — too old)
ELIXIR_VSN="1.18.4"
OTP_MAJOR="25"   # matches Ubuntu 22.04 erlang-nox; releases bundle their own ERTS
if ! command -v elixir &>/dev/null || \
   ! elixir --version 2>/dev/null | grep -q "^Elixir 1\.1[89]\|^Elixir 1\.[2-9]"; then
  info "Installing Elixir ${ELIXIR_VSN} (OTP ${OTP_MAJOR}) from GitHub releases..."
  ELIXIR_ZIP="elixir-otp-${OTP_MAJOR}.zip"
  ELIXIR_URL="https://github.com/elixir-lang/elixir/releases/download/v${ELIXIR_VSN}/${ELIXIR_ZIP}"
  ELIXIR_TMP=$(mktemp -d)
  curl -fsSL "$ELIXIR_URL" -o "${ELIXIR_TMP}/${ELIXIR_ZIP}"
  unzip -q -o "${ELIXIR_TMP}/${ELIXIR_ZIP}" -d /usr/local
  rm -rf "$ELIXIR_TMP"
  info "Elixir $(elixir --version | head -1) installed."
fi

# Caddy
if ! command -v caddy &>/dev/null; then
  info "Installing Caddy..."
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] \
    https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y caddy
fi

# ── 4. Per-service Erlang cookies ────────────────────────────────────────────
info "Generating Erlang cookies..."
for svc in engines portals audit; do
  cookie_file="/opt/pki/.cookies/${svc}"
  if [[ ! -f "$cookie_file" ]]; then
    openssl rand -hex 32 > "$cookie_file"
    chown pki:pki "$cookie_file"
    chmod 400 "$cookie_file"
    info "  Generated cookie for $svc"
  else
    info "  Cookie for $svc already exists, skipping."
  fi
done

# ── 5. SoftHSM2 setup ────────────────────────────────────────────────────────
info "Configuring SoftHSM2..."
SOFTHSM_TOKEN_DIR="/var/lib/softhsm/tokens"
mkdir -p "$SOFTHSM_TOKEN_DIR"
chown pki:pki "$SOFTHSM_TOKEN_DIR"
chmod 700 "$SOFTHSM_TOKEN_DIR"

# Allow pki user to use softhsm2 token directory
if ! groups pki | grep -q softhsm; then
  usermod -aG softhsm pki 2>/dev/null || true
fi

# Write softhsm2.conf for the pki user
cat > /etc/softhsm2.conf << 'EOF'
# SoftHSM2 configuration
directories.tokendir = /var/lib/softhsm/tokens/
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF
chown root:pki /etc/softhsm2.conf
chmod 640 /etc/softhsm2.conf

# ── 6. PostgreSQL ────────────────────────────────────────────────────────────
info "Starting PostgreSQL..."
systemctl enable postgresql
systemctl start postgresql

# Tune max_connections — default 100 is too low for 2 BEAM nodes with multiple repos.
# Each node opens pools for ~7 repos × pool_size ≈ 70 connections per node.
# With 2 nodes (engines + portals) that's ~140 idle + headroom needed.
PG_MAX_CONN=$(sudo -u postgres psql -tAc "SHOW max_connections;" 2>/dev/null || echo "100")
if [[ "$PG_MAX_CONN" -lt 300 ]]; then
  info "Increasing PostgreSQL max_connections from ${PG_MAX_CONN} to 300..."
  sudo -u postgres psql -qc "ALTER SYSTEM SET max_connections = 300;" 2>/dev/null
  systemctl restart postgresql
  info "  ✓ PostgreSQL restarted with max_connections = 300"
else
  info "PostgreSQL max_connections already ${PG_MAX_CONN} (≥300), no change needed."
fi

# ── 7. Caddy ─────────────────────────────────────────────────────────────────
info "Copying Caddyfile..."
if [[ -f "${SCRIPT_DIR}/../Caddyfile" ]]; then
  cp "${SCRIPT_DIR}/../Caddyfile" /etc/caddy/Caddyfile
  chown root:caddy /etc/caddy/Caddyfile
  chmod 640 /etc/caddy/Caddyfile
fi
systemctl enable caddy

# ── 8. systemd service files ─────────────────────────────────────────────────
info "Installing systemd service files..."
for svc_file in "${SCRIPT_DIR}/systemd/"*.service; do
  svc_name=$(basename "$svc_file")
  cp "$svc_file" "/etc/systemd/system/${svc_name}"
  info "  Installed ${svc_name}"
done
systemctl daemon-reload

# ── 9. Generate .env file ────────────────────────────────────────────────────
if [[ ! -f /opt/pki/.env ]]; then
  info "Generating .env with fresh secrets..."
  bash "${SCRIPT_DIR}/generate-env.sh"
else
  info "/opt/pki/.env already exists, skipping. Use 'bash deploy/generate-env.sh --force' to regenerate."
fi

echo ""
echo -e "${GREEN}Installation complete.${NC}"
echo ""
echo "Next steps:"
echo "  1. Review /opt/pki/.env:  sudo cat /opt/pki/.env"
echo "  2. (Optional) Re-generate interactively:  sudo bash deploy/generate-env.sh --force --interactive"
echo "  3. Build releases on build machine:  source .env && bash deploy/build.sh"
echo "  4. Copy tarballs:  scp deploy/releases/*.tar.gz pki@server:~/pki/deploy/releases/"
echo "  5. Deploy:  sudo bash deploy/deploy.sh setup"
