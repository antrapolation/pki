#!/usr/bin/env bash
set -euo pipefail

# Run tests across all Elixir apps in the PKI project.
# Usage:
#   bash scripts/test-all.sh              # Run all tests
#   bash scripts/test-all.sh --only unit  # Skip integration tests
#   bash scripts/test-all.sh --app ca     # Run tests for CA apps only

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/src"

# Apps in dependency order (engines before portals)
APPS=(
  pki_platform_engine
  pki_crypto
  pki_audit_trail
  pki_ca_engine
  pki_ra_engine
  pki_validation
  pki_ca_portal
  pki_ra_portal
  pki_platform_portal
)

# Parse arguments
FILTER=""
APP_FILTER=""
VERBOSE=""
for arg in "$@"; do
  case "$arg" in
    --only) shift; FILTER="--only $1"; shift ;;
    --exclude) shift; FILTER="--exclude $1"; shift ;;
    --app)
      shift
      APP_FILTER="$1"
      shift
      ;;
    --verbose|-v) VERBOSE="1" ;;
    *) FILTER="$FILTER $arg" ;;
  esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

passed=0
failed=0
skipped=0
failed_apps=()

echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  PKI Test Suite${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo ""

for app in "${APPS[@]}"; do
  app_dir="$SRC_DIR/$app"

  # Skip if app directory doesn't exist
  if [[ ! -d "$app_dir" ]]; then
    continue
  fi

  # Skip if no test directory
  if [[ ! -d "$app_dir/test" ]]; then
    continue
  fi

  # Filter by app name if specified
  if [[ -n "$APP_FILTER" ]]; then
    if [[ "$app" != *"$APP_FILTER"* ]]; then
      continue
    fi
  fi

  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"
  echo -e "${CYAN}  Testing: ${app}${NC}"
  echo -e "${CYAN}───────────────────────────────────────────────────${NC}"

  if cd "$app_dir" && mix test $FILTER 2>&1; then
    echo -e "${GREEN}  ✓ ${app} passed${NC}"
    ((passed++))
  else
    echo -e "${RED}  ✗ ${app} FAILED${NC}"
    ((failed++))
    failed_apps+=("$app")
  fi

  echo ""
done

echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Results${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed:  ${passed}${NC}"
echo -e "  ${RED}Failed:  ${failed}${NC}"

if [[ ${#failed_apps[@]} -gt 0 ]]; then
  echo ""
  echo -e "  ${RED}Failed apps:${NC}"
  for fa in "${failed_apps[@]}"; do
    echo -e "    ${RED}• ${fa}${NC}"
  done
  echo ""
  exit 1
else
  echo ""
  echo -e "  ${GREEN}All tests passed.${NC}"
  echo ""
  exit 0
fi
