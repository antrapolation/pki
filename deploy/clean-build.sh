#!/usr/bin/env bash
# deploy/clean-build.sh — Remove macOS/ARM build artifacts before linux/amd64 build
#
# When building inside a cross-platform container, the host's _build/ and deps/
# directories contain ARM-compiled .beam files and native objects that conflict
# with the x86 target. This script cleans them so mix compiles fresh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/src"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
info() { echo -e "${GREEN}[clean]${NC} $*"; }

info "Cleaning build artifacts for cross-platform build..."

# Clean root-level build (3-release configuration)
rm -rf "$REPO_ROOT/_build/prod" 2>/dev/null || true

# Clean NIF .so files from all src/ apps (architecture-specific)
for app_dir in "$SRC"/*/; do
  [[ -d "$app_dir/priv" ]] && find "$app_dir/priv" -name '*.so' -delete 2>/dev/null || true
done

# Clean kaz_sign if present
KAZ_SIGN_DIR="$REPO_ROOT/../PQC-KAZ/SIGN/bindings/elixir"
if [[ -d "$KAZ_SIGN_DIR" ]]; then
  rm -rf "$KAZ_SIGN_DIR/_build/prod" 2>/dev/null || true
  find "$KAZ_SIGN_DIR/priv" -name '*.so' -delete 2>/dev/null || true
fi

info "Clean complete."
