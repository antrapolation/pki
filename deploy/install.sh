#!/usr/bin/env bash
# deploy/install.sh — One-time server setup for PKI CA System (BEAM direct deployment)
#
# Run as root on a fresh Ubuntu 22.04 / Debian 12 server:
#   sudo bash deploy/install.sh
#
# What this does:
#   1. Installs system packages (Erlang/OTP, Elixir, PostgreSQL, SoftHSM2, Caddy)
#   2. Creates the 'pki' OS user
#   3. Sets up /opt/pki/ directory structure
#   4. Generates per-service Erlang cookies
#   5. Configures SoftHSM2 token directory permissions
#   6. Enables and starts PostgreSQL

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[install]${NC} $*"; }
warn()    { echo -e "${YELLOW}[install]${NC} $*"; }
die()     { echo -e "${RED}[install] ERROR:${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash deploy/install.sh"

# ── 1. System packages ───────────────────────────────────────────────────────
info "Installing system packages..."
apt-get update -qq

# Erlang/OTP + Elixir via Erlang Solutions repo
if ! command -v erl &>/dev/null; then
  wget -q https://packages.erlang-solutions.com/erlang-solutions_2.0_all.deb
  dpkg -i erlang-solutions_2.0_all.deb
  rm erlang-solutions_2.0_all.deb
  apt-get update -qq
fi
apt-get install -y --no-install-recommends \
  esl-erlang elixir \
  postgresql postgresql-client \
  softhsm2 \
  libssl-dev \
  curl ca-certificates

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

# ── 2. Create pki user ───────────────────────────────────────────────────────
if ! id pki &>/dev/null; then
  info "Creating 'pki' system user..."
  useradd --system --shell /bin/bash --home /opt/pki --create-home pki
else
  info "'pki' user already exists, skipping."
fi

# ── 3. Directory structure ───────────────────────────────────────────────────
info "Creating /opt/pki directory structure..."
mkdir -p /opt/pki/{releases/{ca_engine,ra_engine,ca_portal,ra_portal,platform_portal,validation},.cookies,logs}
chown -R pki:pki /opt/pki
chmod 750 /opt/pki/.cookies

# ── 4. Per-service Erlang cookies ────────────────────────────────────────────
info "Generating Erlang cookies..."
for svc in ca_engine ra_engine ca_portal ra_portal platform_portal validation; do
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

# ── 7. Caddy ─────────────────────────────────────────────────────────────────
info "Copying Caddyfile..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# ── 9. .env file ─────────────────────────────────────────────────────────────
if [[ ! -f /opt/pki/.env ]]; then
  if [[ -f "${SCRIPT_DIR}/.env.production" ]]; then
    cp "${SCRIPT_DIR}/.env.production" /opt/pki/.env
    chown pki:pki /opt/pki/.env
    chmod 600 /opt/pki/.env
    warn "Copied .env.production to /opt/pki/.env — EDIT IT before starting services!"
  fi
else
  info "/opt/pki/.env already exists, skipping."
fi

echo ""
echo -e "${GREEN}Installation complete.${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit /opt/pki/.env with your actual secrets"
echo "  2. Run: sudo -u postgres psql -f scripts/init-databases.sh"
echo "  3. Run: bash deploy/build.sh   (on build machine)"
echo "  4. Run: bash deploy/deploy.sh  (on this server)"
echo "  5. Run: systemctl start caddy"
