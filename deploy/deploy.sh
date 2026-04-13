#!/usr/bin/env bash
# deploy/deploy.sh — Deploy (or upgrade) PKI releases on the server
#
# Run on the server from the repo root:
#   bash deploy/deploy.sh              # deploy all services
#   bash deploy/deploy.sh engines      # deploy one service
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

# Generate .env if missing (setup mode) or require it (other modes)
if [[ ! -f /opt/pki/.env ]]; then
  if [[ "${1:-}" == "setup" && -f "$SCRIPT_DIR/generate-env.sh" ]]; then
    info "No .env found — generating with fresh secrets..."
    bash "$SCRIPT_DIR/generate-env.sh"
  else
    die "/opt/pki/.env not found — run: sudo bash deploy/generate-env.sh"
  fi
fi

# ── Database names (shared DB, schema-per-tenant) ────────────────────────────
PKI_DATABASES=(pki_ca_engine pki_ra_engine pki_validation pki_audit_trail pki_platform)

ensure_databases() {
  info "Ensuring PostgreSQL databases exist..."

  # Load POSTGRES_PASSWORD from .env
  local pg_pass
  pg_pass=$(grep '^POSTGRES_PASSWORD=' /opt/pki/.env | cut -d= -f2-)
  [[ -n "$pg_pass" ]] || die "POSTGRES_PASSWORD not set in /opt/pki/.env"

  # Set the postgres user password (idempotent)
  sudo -u postgres psql -qc "ALTER USER postgres PASSWORD '${pg_pass}';" 2>/dev/null || true

  for db in "${PKI_DATABASES[@]}"; do
    if sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${db}'" | grep -q 1; then
      info "  ✓ $db exists"
    else
      sudo -u postgres createdb "$db"
      info "  Created $db"
    fi
  done
}

ensure_caddy() {
  if command -v caddy &>/dev/null; then
    info "Starting Caddy (TLS termination)..."
    systemctl enable caddy 2>/dev/null || true
    systemctl reload-or-restart caddy
    if systemctl is-active --quiet caddy; then
      info "  ✓ Caddy is running"
    else
      warn "  Caddy failed to start — check: journalctl -u caddy -n 50"
    fi
  else
    warn "Caddy not installed — skipping TLS setup"
  fi
}

# Map: internal_name → systemd_service_name, tarball_prefix, install_dir
declare -A SVC_SYSTEMD=(
  [engines]=pki-engines
  [portals]=pki-portals
  [audit]=pki-audit
)

declare -A SVC_TARBALL=(
  [engines]=pki_engines
  [portals]=pki_portals
  [audit]=pki_audit
)

run_migrations() {
  local svc="$1"       # e.g. engines
  local bin="${INSTALL_BASE}/${svc}/bin/${SVC_TARBALL[$svc]}"

  [[ -x "$bin" ]] || { warn "Binary not found: $bin — skipping migrations"; return; }

  info "  Running migrations for $svc..."
  sudo -u pki env $(grep -v '^#' /opt/pki/.env | xargs) \
    "$bin" eval "PkiSystem.Release.migrate()" 2>&1 \
    || warn "Migration returned non-zero for $svc (may be normal if already applied)"
}

deploy_service() {
  local svc="$1"   # internal name, e.g. engines
  local systemd_name="${SVC_SYSTEMD[$svc]}"
  local tarball_prefix="${SVC_TARBALL[$svc]}"
  local install_dir="${INSTALL_BASE}/${svc}"

  # Find source: tarball (from build.sh) or local _build (built on server)
  local tarball=""
  local local_build=""
  tarball=$(ls -t "${RELEASES_DIR}/${tarball_prefix}-"*.tar.gz 2>/dev/null | head -1) || true

  # Also check for locally-built release (when building on the server directly)
  local repo_root
  repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
  if [[ -d "${repo_root}/_build/prod/rel/${tarball_prefix}" ]]; then
    local_build="${repo_root}/_build/prod/rel/${tarball_prefix}"
  fi

  if [[ -z "$tarball" && -z "$local_build" ]]; then
    warn "No tarball in $RELEASES_DIR and no local build in _build/prod/rel/${tarball_prefix} — skipping $svc"
    return
  fi

  local source_desc
  if [[ -n "$tarball" ]]; then
    source_desc="tarball $(basename "$tarball")"
  else
    source_desc="local build ${local_build}"
  fi
  info "Deploying $svc from ${source_desc}..."

  # Stop service (|| true: service may be in restart cycle, stop job gets cancelled)
  if systemctl is-active --quiet "$systemd_name" 2>/dev/null || \
     systemctl is-activating "$systemd_name" 2>/dev/null; then
    info "  Stopping $systemd_name..."
    systemctl stop "$systemd_name" 2>/dev/null || true
    # Wait for OS to release ports — BEAM sockets can linger briefly after process exit
    sleep 3
  fi

  # Backup current release
  if [[ -d "$install_dir/bin" ]]; then
    local backup="${install_dir}.bak"
    rm -rf "$backup"
    cp -a "$install_dir" "$backup"
    info "  Backup saved to ${backup}"
  fi

  # Install new release
  rm -rf "$install_dir"
  mkdir -p "$install_dir"
  if [[ -n "$tarball" ]]; then
    tar -xzf "$tarball" -C "$install_dir"
  else
    cp -a "${local_build}/." "$install_dir/"
  fi
  chown -R pki:pki "$install_dir"
  info "  Installed to $install_dir"

  # Inject Erlang cookie from /opt/pki/.cookies/ into the release
  local cookie_file="/opt/pki/.cookies/${svc}"
  if [[ -f "$cookie_file" ]]; then
    cp "$cookie_file" "${install_dir}/releases/COOKIE"
    chown pki:pki "${install_dir}/releases/COOKIE"
    chmod 400 "${install_dir}/releases/COOKIE"
    info "  Injected Erlang cookie"
  else
    warn "  No cookie file at $cookie_file — release will use build-time cookie"
  fi

  # Run migrations (only engines release owns the databases)
  case "$svc" in
    engines) run_migrations "$svc" ;;
    *) info "  Skipping migrations for $svc (engines release handles DB)" ;;
  esac

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
    # Ensure PostgreSQL databases exist before deploying
    ensure_databases

    # Deploy in dependency order: engines first (owns DBs), then portals, then audit
    deploy_service engines
    deploy_service portals
    deploy_service audit

    # Start Caddy for TLS termination
    ensure_caddy

    echo ""
    info "All services deployed."
    echo ""
    echo "Check status:  systemctl status 'pki-*' caddy"
    echo "Tail logs:     journalctl -u pki-engines -f"
    echo "Remote shell:  /opt/pki/releases/engines/bin/pki_engines remote"
    ;;

  engines)  deploy_service engines ;;
  portals)  deploy_service portals ;;
  audit)    deploy_service audit ;;

  migrate)
    info "Running all DB migrations..."
    # Only the engines release owns databases
    run_migrations engines
    ;;

  rollback)
    svc="${2:-}"
    [[ -n "$svc" ]] || die "Usage: deploy.sh rollback <service>"
    backup="${INSTALL_BASE}/${svc}.bak"
    [[ -d "$backup" ]] || die "No backup found at $backup"
    systemctl stop "${SVC_SYSTEMD[$svc]}"
    rm -rf "${INSTALL_BASE}/${svc}"
    mv "$backup" "${INSTALL_BASE}/${svc}"
    chown -R pki:pki "${INSTALL_BASE}/${svc}"
    systemctl start "${SVC_SYSTEMD[$svc]}"
    info "Rolled back $svc"
    ;;

  setup)
    # First-run setup: create DBs, deploy all services, start Caddy
    info "=== First-run setup ==="
    ensure_databases

    # Init SoftHSM2 token if not already done
    source /opt/pki/.env
    if sudo -u pki softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${SOFTHSM_TOKEN_LABEL:-PkiCA}"; then
      info "SoftHSM2 token already initialised"
    else
      if [[ -n "${SOFTHSM_TOKEN_LABEL:-}" && -n "${SOFTHSM_SO_PIN:-}" && -n "${SOFTHSM_USER_PIN:-}" ]]; then
        info "Initialising SoftHSM2 token..."
        sudo -u pki softhsm2-util --init-token --free \
          --label "$SOFTHSM_TOKEN_LABEL" \
          --so-pin "$SOFTHSM_SO_PIN" \
          --pin "$SOFTHSM_USER_PIN"
        info "  ✓ Token initialised"
      else
        warn "SoftHSM vars not set in .env — skipping token init"
      fi
    fi

    deploy_service engines
    deploy_service portals
    deploy_service audit
    ensure_caddy

    echo ""
    info "=== Setup complete ==="
    echo ""
    echo "Verify:"
    echo "  curl -s http://localhost:4001/health"
    echo "  curl -s https://ca.straptrust.com"
    echo "  systemctl status 'pki-*' caddy"
    ;;

  *)
    echo "Usage: $0 [all|engines|portals|audit|migrate|setup|rollback <svc>]"
    exit 1
    ;;
esac
