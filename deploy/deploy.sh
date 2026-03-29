#!/usr/bin/env bash
# deploy/deploy.sh — Deploy (or upgrade) PKI releases on the server
#
# Run on the server from the repo root:
#   bash deploy/deploy.sh              # deploy all services
#   bash deploy/deploy.sh ca-engine    # deploy one service
#   bash deploy/deploy.sh migrate      # run DB migrations only
#
# Expects tarballs in deploy/releases/ (produced by build.sh).
# Services are stopped, upgraded, migrated, then restarted.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASES_DIR="$SCRIPT_DIR/releases"
INSTALL_BASE="/opt/pki/releases"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[deploy]${NC} $*"; }
die()   { echo -e "${RED}[deploy] ERROR:${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash deploy/deploy.sh"
[[ -f /opt/pki/.env ]] || die "/opt/pki/.env not found — run install.sh first"

# Map: internal_name → systemd_service_name, tarball_prefix, install_dir
declare -A SVC_SYSTEMD=(
  [ca_engine]=pki-ca-engine
  [ra_engine]=pki-ra-engine
  [ca_portal]=pki-ca-portal
  [ra_portal]=pki-ra-portal
  [platform_portal]=pki-platform-portal
  [validation]=pki-validation
)

declare -A SVC_TARBALL=(
  [ca_engine]=pki_ca_engine
  [ra_engine]=pki_ra_engine
  [ca_portal]=pki_ca_portal
  [ra_portal]=pki_ra_portal
  [platform_portal]=pki_platform_portal
  [validation]=pki_validation
)

run_migrations() {
  local svc="$1"       # e.g. ca_engine
  local bin="${INSTALL_BASE}/${svc}/bin/${SVC_TARBALL[$svc]}"

  [[ -x "$bin" ]] || { warn "Binary not found: $bin — skipping migrations"; return; }

  info "  Running migrations for $svc..."
  sudo -u pki env $(grep -v '^#' /opt/pki/.env | xargs) \
    "$bin" eval "${SVC_TARBALL[$svc]^}.Release.migrate()" 2>&1 \
    || warn "Migration returned non-zero for $svc (may be normal if already applied)"
}

deploy_service() {
  local svc="$1"   # internal name, e.g. ca_engine
  local systemd_name="${SVC_SYSTEMD[$svc]}"
  local tarball_prefix="${SVC_TARBALL[$svc]}"
  local install_dir="${INSTALL_BASE}/${svc}"

  # Find latest tarball
  local tarball
  tarball=$(ls -t "${RELEASES_DIR}/${tarball_prefix}-"*.tar.gz 2>/dev/null | head -1)
  [[ -n "$tarball" ]] || { warn "No tarball found for $svc in $RELEASES_DIR — skipping"; return; }

  info "Deploying $svc from $(basename "$tarball")..."

  # Stop service
  if systemctl is-active --quiet "$systemd_name" 2>/dev/null; then
    info "  Stopping $systemd_name..."
    systemctl stop "$systemd_name"
  fi

  # Backup current release
  if [[ -d "$install_dir/bin" ]]; then
    local backup="${install_dir}.bak"
    rm -rf "$backup"
    cp -a "$install_dir" "$backup"
    info "  Backup saved to ${backup}"
  fi

  # Extract new release
  rm -rf "$install_dir"
  mkdir -p "$install_dir"
  tar -xzf "$tarball" -C "$install_dir"
  chown -R pki:pki "$install_dir"
  info "  Extracted to $install_dir"

  # Run migrations
  run_migrations "$svc"

  # Start service
  systemctl enable "$systemd_name"
  systemctl start "$systemd_name"
  info "  Started $systemd_name"

  # Quick health check
  sleep 3
  if systemctl is-active --quiet "$systemd_name"; then
    info "  ✓ $systemd_name is running"
  else
    warn "  $systemd_name failed to start — check: journalctl -u $systemd_name -n 50"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
TARGET="${1:-all}"

case "$TARGET" in
  all)
    # Deploy in dependency order
    deploy_service ca_engine
    deploy_service validation
    deploy_service ra_engine
    deploy_service ca_portal
    deploy_service ra_portal
    deploy_service platform_portal

    echo ""
    info "All services deployed."
    echo ""
    echo "Check status:  systemctl status 'pki-*'"
    echo "Tail logs:     journalctl -u pki-ca-engine -f"
    echo "Remote shell:  /opt/pki/releases/ca_engine/bin/pki_ca_engine remote"
    ;;

  ca-engine)    deploy_service ca_engine ;;
  ra-engine)    deploy_service ra_engine ;;
  ca-portal)    deploy_service ca_portal ;;
  ra-portal)    deploy_service ra_portal ;;
  platform)     deploy_service platform_portal ;;
  validation)   deploy_service validation ;;

  migrate)
    info "Running all DB migrations..."
    for svc in ca_engine ra_engine validation platform_portal; do
      run_migrations "$svc"
    done
    ;;

  rollback)
    svc="${2:-}"
    [[ -n "$svc" ]] || die "Usage: deploy.sh rollback <service>"
    svc="${svc//-/_}"
    backup="${INSTALL_BASE}/${svc}.bak"
    [[ -d "$backup" ]] || die "No backup found at $backup"
    systemctl stop "${SVC_SYSTEMD[$svc]}"
    rm -rf "${INSTALL_BASE}/${svc}"
    mv "$backup" "${INSTALL_BASE}/${svc}"
    chown -R pki:pki "${INSTALL_BASE}/${svc}"
    systemctl start "${SVC_SYSTEMD[$svc]}"
    info "Rolled back $svc"
    ;;

  *)
    echo "Usage: $0 [all|ca-engine|ra-engine|ca-portal|ra-portal|platform|validation|migrate|rollback <svc>]"
    exit 1
    ;;
esac
