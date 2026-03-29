#!/usr/bin/env bash
# deploy/build.sh — Build all Mix releases for production
#
# Run on your build machine (or CI) from the repo root:
#   bash deploy/build.sh
#
# Outputs tarballs to deploy/releases/:
#   deploy/releases/pki_ca_engine-<vsn>.tar.gz
#   deploy/releases/pki_ra_engine-<vsn>.tar.gz
#   ...
#
# The signing salts are baked in at compile time — source your .env first:
#   source .env && bash deploy/build.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/src"
OUT="$REPO_ROOT/deploy/releases"
mkdir -p "$OUT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[build]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build]${NC} $*"; }
die()   { echo -e "${RED}[build] ERROR:${NC} $*" >&2; exit 1; }

# Ensure signing salts are available at compile time
[[ -n "${CA_PORTAL_SIGNING_SALT:-}" ]]   || warn "CA_PORTAL_SIGNING_SALT not set — using hardcoded default"
[[ -n "${RA_PORTAL_SIGNING_SALT:-}" ]]   || warn "RA_PORTAL_SIGNING_SALT not set — using hardcoded default"
[[ -n "${PLATFORM_SIGNING_SALT:-}" ]]    || warn "PLATFORM_SIGNING_SALT not set — using hardcoded default"

build_service() {
  local name="$1"      # pki_ca_engine
  local dir="$2"       # src/pki_ca_engine

  info "Building $name..."
  cd "$REPO_ROOT/$dir"

  MIX_ENV=prod mix deps.get --only prod
  MIX_ENV=prod mix assets.deploy 2>/dev/null || true   # portals only
  MIX_ENV=prod mix release --overwrite

  # Find the generated release tarball or create one
  local rel_dir="_build/prod/rel/${name}"
  local vsn
  vsn=$(cat "${rel_dir}/releases/start_erl.data" | awk '{print $2}' 2>/dev/null || echo "0.1.0")

  local tarball="${OUT}/${name}-${vsn}.tar.gz"
  tar -czf "$tarball" -C "${rel_dir}" .
  info "  → ${tarball}"
}

# Services in dependency order
build_service pki_ca_engine   src/pki_ca_engine
build_service pki_ra_engine   src/pki_ra_engine
build_service pki_validation  src/pki_validation
build_service pki_ca_portal   src/pki_ca_portal
build_service pki_ra_portal   src/pki_ra_portal
build_service pki_platform_portal src/pki_platform_portal

echo ""
info "All releases built in deploy/releases/"
ls -lh "$OUT"/*.tar.gz
echo ""
echo "Copy to server and run: bash deploy/deploy.sh"
