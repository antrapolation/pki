#!/usr/bin/env bash
# deploy/build.sh — Build 3 consolidated Mix releases for production
#
# Run on your build machine (or CI) from the repo root:
#   bash deploy/build.sh
#
# Outputs tarballs to deploy/releases/:
#   deploy/releases/pki_engines-<vsn>.tar.gz
#   deploy/releases/pki_portals-<vsn>.tar.gz
#   deploy/releases/pki_audit-<vsn>.tar.gz
#
# The signing salts are baked in at compile time — source your .env first:
#   source .env && bash deploy/build.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/deploy/releases"
mkdir -p "$OUT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[build]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build]${NC} $*"; }
die()   { echo -e "${RED}[build] ERROR:${NC} $*" >&2; exit 1; }

# Ensure signing salts are available at compile time
[[ -n "${CA_PORTAL_SIGNING_SALT:-}" ]]   || die "CA_PORTAL_SIGNING_SALT not set — set it in .env before building"
[[ -n "${RA_PORTAL_SIGNING_SALT:-}" ]]   || die "RA_PORTAL_SIGNING_SALT not set — set it in .env before building"
[[ -n "${PLATFORM_SIGNING_SALT:-}" ]]    || die "PLATFORM_SIGNING_SALT not set — set it in .env before building"
[[ -n "${CA_PORTAL_ENCRYPTION_SALT:-}" ]]   || die "CA_PORTAL_ENCRYPTION_SALT not set — set it in .env before building"
[[ -n "${RA_PORTAL_ENCRYPTION_SALT:-}" ]]   || die "RA_PORTAL_ENCRYPTION_SALT not set — set it in .env before building"
[[ -n "${PLATFORM_ENCRYPTION_SALT:-}" ]]    || die "PLATFORM_ENCRYPTION_SALT not set — set it in .env before building"

cd "$REPO_ROOT"

# ── Fetch deps and compile assets ────────────────────────────────────────────
info "Fetching dependencies..."
MIX_ENV=prod mix deps.get --only prod

info "Deploying assets (portals)..."
MIX_ENV=prod mix assets.deploy 2>/dev/null || true

# ── Build releases ───────────────────────────────────────────────────────────
RELEASES=(pki_engines pki_portals pki_audit)

for release in "${RELEASES[@]}"; do
  info "Building release: $release..."
  MIX_ENV=prod mix release "$release" --overwrite

  # Package the release as a tarball
  local_rel_dir="_build/prod/rel/${release}"
  vsn=$(cat "${local_rel_dir}/releases/start_erl.data" | awk '{print $2}' 2>/dev/null || echo "0.2.0")

  tarball="${OUT}/${release}-${vsn}.tar.gz"
  tar -czf "$tarball" -C "${local_rel_dir}" .
  info "  → ${tarball}"
done

echo ""
info "All releases built in deploy/releases/"
ls -lh "$OUT"/*.tar.gz
echo ""
echo "Copy to server and run: bash deploy/deploy.sh"
