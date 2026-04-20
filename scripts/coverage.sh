#!/usr/bin/env bash
# scripts/coverage.sh — run `mix test --cover` across every wired
# package and print a one-line summary per package.
#
# Usage:
#   ./scripts/coverage.sh                   # run all wired packages
#   ./scripts/coverage.sh pki_crypto        # run only pki_crypto
#
# Exit status 0 if every package met its 70% threshold,
# 1 otherwise. Full per-module breakdowns land in each package's
# `_build/test/cover/` directory (HTML in `cover/*.html`).

set -uo pipefail

# ---------------------------------------------------------------------------
# Packages with test_coverage wired in their mix.exs.
# Keep in sync with the grep below if you wire a new one.
# ---------------------------------------------------------------------------
PACKAGES=(
  pki_crypto
  pki_ca_engine
  pki_ra_engine
  pki_validation
  pki_platform_engine
  pki_platform_portal
  pki_tenant
  pki_tenant_web
  pki_mnesia
)

if [ $# -gt 0 ]; then
  PACKAGES=("$@")
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS=()
ANY_FAILED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

for pkg in "${PACKAGES[@]}"; do
  pkg_dir="$REPO_ROOT/src/$pkg"
  if [ ! -d "$pkg_dir" ]; then
    echo -e "${YELLOW}[skip]${NC} $pkg — directory not found"
    continue
  fi

  echo
  echo "=== $pkg ==="
  cd "$pkg_dir"

  # Capture full output; grep for the totals line.
  if output=$(mix test --cover 2>&1); then
    exit_code=0
  else
    exit_code=$?
  fi

  total_line=$(echo "$output" | grep -E "^\s*[0-9]+\.[0-9]+% \| Total" | tail -1)
  threshold_line=$(echo "$output" | grep -E "threshold not met" | head -1)

  if [ -z "$total_line" ]; then
    echo -e "${RED}[fail]${NC} $pkg — no coverage output (see errors above)"
    echo "$output" | tail -20
    ANY_FAILED=1
    RESULTS+=("$pkg: NO OUTPUT")
    continue
  fi

  total_pct=$(echo "$total_line" | awk '{print $1}')

  if [ -n "$threshold_line" ]; then
    echo -e "${RED}[fail]${NC} $pkg — $total_pct (below threshold)"
    ANY_FAILED=1
    RESULTS+=("$pkg: $total_pct (below threshold)")
  else
    echo -e "${GREEN}[ok]${NC}   $pkg — $total_pct"
    RESULTS+=("$pkg: $total_pct")
  fi
done

echo
echo "=========================================="
echo " Coverage summary"
echo "=========================================="
for r in "${RESULTS[@]}"; do
  echo "  $r"
done
echo "=========================================="

exit $ANY_FAILED
