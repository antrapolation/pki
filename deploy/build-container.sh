#!/usr/bin/env bash
# deploy/build-container.sh — Build linux/amd64 releases using Podman
#
# Run from repo root:
#   bash deploy/build-container.sh              # build all services
#   bash deploy/build-container.sh --test       # run tests first, then build
#   bash deploy/build-container.sh --test-only  # run tests only, no release build
#   bash deploy/build-container.sh --shell      # drop into builder shell for debugging
#
# First run builds the builder image (~5 min with QEMU emulation).
# Subsequent runs reuse the cached image (~2-3 min for full build).
#
# Output: deploy/releases/*.tar.gz (linux/amd64 binaries)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
IMAGE_NAME="pki-builder"
PLATFORM="linux/amd64"

# The repo name inside the workspace (e.g., "pki")
REPO_NAME="$(basename "$REPO_ROOT")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[build]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build]${NC} $*"; }
die()   { echo -e "${RED}[build] ERROR:${NC} $*" >&2; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────────────
RUN_TESTS=false
TEST_ONLY=false
SHELL_MODE=false

for arg in "$@"; do
  case "$arg" in
    --test)      RUN_TESTS=true ;;
    --test-only) RUN_TESTS=true; TEST_ONLY=true ;;
    --shell)     SHELL_MODE=true ;;
    --rebuild)   podman rmi "$IMAGE_NAME" 2>/dev/null || true ;;
    *)           warn "Unknown argument: $arg" ;;
  esac
done

# ── Ensure QEMU user-static is available for cross-platform emulation ────────
if ! podman run --rm --platform "$PLATFORM" docker.io/library/alpine:3.20 uname -m &>/dev/null 2>&1; then
  warn "QEMU emulation not detected. Registering binfmt handlers..."
  podman run --rm --privileged docker.io/tonistiigi/binfmt --install amd64 || \
    die "Failed to set up QEMU. Install qemu-user-static: brew install qemu"
fi

# ── Build the builder image (cached after first run) ─────────────────────────
if ! podman image exists "$IMAGE_NAME" 2>/dev/null; then
  info "Building builder image (first time — takes ~5 min with QEMU)..."
  podman build \
    --platform "$PLATFORM" \
    -t "$IMAGE_NAME" \
    -f deploy/Dockerfile.builder \
    "$REPO_ROOT"
else
  info "Using cached builder image '$IMAGE_NAME'"
fi

# ── Prepare output directory ─────────────────────────────────────────────────
mkdir -p "$REPO_ROOT/deploy/releases"

# ── Load .env for signing salts ──────────────────────────────────────────────
ENV_ARGS=()
if [[ -f "$REPO_ROOT/.env" ]]; then
  info "Loading .env for signing salts..."
  # Pass only the variables needed at compile time
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    case "$key" in
      PLATFORM_SIGNING_SALT|PLATFORM_ENCRYPTION_SALT|SECRET_KEY_BASE)
        ENV_ARGS+=("-e" "${key}=${value}")
        ;;
    esac
  done < "$REPO_ROOT/.env"
fi

# ── Determine what to run inside the container ───────────────────────────────
# Mount the entire workspace so relative path deps (e.g., ../../../PQC-KAZ) resolve.
# Working directory is set to the pki repo inside the workspace.
MOUNT_ARGS=(-v "$WORKSPACE_ROOT:/workspace:z" -w "/workspace/$REPO_NAME")

if $SHELL_MODE; then
  info "Dropping into builder shell (linux/amd64)..."
  exec podman run --rm -it \
    --platform "$PLATFORM" \
    "${MOUNT_ARGS[@]}" \
    "${ENV_ARGS[@]}" \
    "$IMAGE_NAME" \
    bash

elif $TEST_ONLY; then
  info "Running tests (linux/amd64)..."
  podman run --rm \
    --platform "$PLATFORM" \
    "${MOUNT_ARGS[@]}" \
    "${ENV_ARGS[@]}" \
    "$IMAGE_NAME" \
    bash -c "bash deploy/clean-build.sh && bash scripts/test-all.sh --exclude integration"

elif $RUN_TESTS; then
  info "Running tests then building releases (linux/amd64)..."
  podman run --rm \
    --platform "$PLATFORM" \
    "${MOUNT_ARGS[@]}" \
    "${ENV_ARGS[@]}" \
    "$IMAGE_NAME" \
    bash -c "bash deploy/clean-build.sh && bash scripts/test-all.sh --exclude integration && bash deploy/build.sh"

else
  info "Building releases (linux/amd64)..."
  podman run --rm \
    --platform "$PLATFORM" \
    "${MOUNT_ARGS[@]}" \
    "${ENV_ARGS[@]}" \
    "$IMAGE_NAME" \
    bash -c "bash deploy/clean-build.sh && bash deploy/build.sh"
fi

# ── Report results ───────────────────────────────────────────────────────────
echo ""
if [[ -d "$REPO_ROOT/deploy/releases" ]] && ls "$REPO_ROOT/deploy/releases"/*.tar.gz &>/dev/null; then
  info "Releases built successfully:"
  echo ""
  ls -lh "$REPO_ROOT/deploy/releases"/*.tar.gz
  echo ""

  # Verify architecture
  info "Verifying architecture..."
  SAMPLE_TAR=$(ls "$REPO_ROOT/deploy/releases"/*.tar.gz | head -1)
  TMPDIR=$(mktemp -d)
  tar -xzf "$SAMPLE_TAR" -C "$TMPDIR" --include='*/beam.smp' 2>/dev/null || \
  tar -xzf "$SAMPLE_TAR" -C "$TMPDIR" --wildcards '*/beam.smp' 2>/dev/null || true

  BEAM_BIN=$(find "$TMPDIR" -name 'beam.smp' -type f 2>/dev/null | head -1)
  if [[ -n "$BEAM_BIN" ]]; then
    ARCH=$(file "$BEAM_BIN" | grep -o 'x86-64\|x86_64\|aarch64\|ARM64' || echo "unknown")
    if [[ "$ARCH" =~ x86 ]]; then
      echo -e "  ${GREEN}Architecture: x86-64 (correct for production)${NC}"
    else
      echo -e "  ${RED}Architecture: $ARCH (WRONG — expected x86-64)${NC}"
    fi
  fi
  rm -rf "$TMPDIR"

  echo ""
  echo "Next steps:"
  echo "  scp deploy/releases/*.tar.gz pki@your-server:~/deploy/releases/"
  echo "  ssh pki@your-server 'sudo bash deploy/deploy.sh'"
fi
