#!/usr/bin/env bash
# dev.sh — Start all PKI services directly on the host (no containers for Elixir apps)
# PostgreSQL still runs in its container (localhost:5434)
# SoftHSM2 still runs in its container
#
# Usage:
#   ./dev.sh              — start all services
#   ./dev.sh ca-engine    — start only CA engine
#   ./dev.sh ca-portal    — start only CA portal
#   ./dev.sh ra-engine    — start only RA engine
#   ./dev.sh ra-portal    — start only RA portal
#   ./dev.sh validation   — start only validation service
#   ./dev.sh stop         — kill all background services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/src"
LOG_DIR="$SCRIPT_DIR/.dev-logs"
PID_FILE="$SCRIPT_DIR/.dev-pids"

# ── Mise / Elixir path ───────────────────────────────────────────────────────
export PATH="$HOME/.local/bin:$PATH"
eval "$(mise activate bash 2>/dev/null)" || true

# ── Shared env vars ──────────────────────────────────────────────────────────
# PostgreSQL runs in container on host port 5434
PG_PASS="TbusTrh911CaS9NcPlWvomDVduFojslMLSxBbmZJBXQ="
PG_URL_BASE="ecto://postgres:${PG_PASS}@localhost:5434"

export INTERNAL_API_SECRET="TsHbWht79gety1MN57N0QphOpoU28NVruo5JoMW1/uw="
export COOKIE_SECURE="false"
export SECRET_KEY_BASE="rVZ3s99uzntf1L5NpyautO5qAXu8yFFRjmVKYOT39fQqF8Hql1sxO6uXFepW46YiyumSnqrbByLF3Ofooecusw=="

# ── Stop command ─────────────────────────────────────────────────────────────
stop_all() {
  if [[ -f "$PID_FILE" ]]; then
    echo "Stopping all dev services..."
    while IFS= read -r pid; do
      kill "$pid" 2>/dev/null && echo "  killed PID $pid" || true
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  else
    echo "No PID file found — killing by process name..."
    pkill -f "mix phx.server" 2>/dev/null || true
    pkill -f "mix run" 2>/dev/null || true
  fi
}

# ── Service starters ─────────────────────────────────────────────────────────
start_ca_engine() {
  echo "▶ Starting CA Engine (port 4001)..."
  mkdir -p "$LOG_DIR"
  cd "$SRC/pki_ca_engine"
  POSTGRES_PASSWORD="$PG_PASS" \
  POSTGRES_PORT="5434" \
  CA_ENGINE_DB="pki_ca_engine" \
  AUDIT_TRAIL_DB="pki_audit_trail" \
  INTERNAL_API_SECRET="$INTERNAL_API_SECRET" \
  VALIDATION_URL="http://localhost:4005" \
  PORT="4001" \
  MIX_ENV=dev \
    mix do ecto.migrate --quiet, phx.server \
    > "$LOG_DIR/ca-engine.log" 2>&1 &
  echo $! >> "$PID_FILE"
  echo "  PID $! → logs: $LOG_DIR/ca-engine.log"
}

start_ca_portal() {
  echo "▶ Starting CA Portal (port 4002)..."
  mkdir -p "$LOG_DIR"
  cd "$SRC/pki_ca_portal"
  CA_ENGINE_URL="http://localhost:4001" \
  INTERNAL_API_SECRET="$INTERNAL_API_SECRET" \
  COOKIE_SECURE="false" \
  PORT=4002 \
  MIX_ENV=dev \
    mix phx.server \
    > "$LOG_DIR/ca-portal.log" 2>&1 &
  echo $! >> "$PID_FILE"
  echo "  PID $! → logs: $LOG_DIR/ca-portal.log"
}

start_ra_engine() {
  echo "▶ Starting RA Engine (port 4003)..."
  mkdir -p "$LOG_DIR"
  cd "$SRC/pki_ra_engine"
  POSTGRES_PASSWORD="$PG_PASS" \
  POSTGRES_PORT="5434" \
  RA_ENGINE_DB="pki_ra_engine" \
  INTERNAL_API_SECRET="$INTERNAL_API_SECRET" \
  CA_ENGINE_URL="http://localhost:4001" \
  PORT="4003" \
  MIX_ENV=dev \
    mix do ecto.migrate --quiet, phx.server \
    > "$LOG_DIR/ra-engine.log" 2>&1 &
  echo $! >> "$PID_FILE"
  echo "  PID $! → logs: $LOG_DIR/ra-engine.log"
}

start_ra_portal() {
  echo "▶ Starting RA Portal (port 4004)..."
  mkdir -p "$LOG_DIR"
  cd "$SRC/pki_ra_portal"
  RA_ENGINE_URL="http://localhost:4003" \
  INTERNAL_API_SECRET="$INTERNAL_API_SECRET" \
  COOKIE_SECURE="false" \
  PORT=4004 \
  MIX_ENV=dev \
    mix phx.server \
    > "$LOG_DIR/ra-portal.log" 2>&1 &
  echo $! >> "$PID_FILE"
  echo "  PID $! → logs: $LOG_DIR/ra-portal.log"
}

start_validation() {
  echo "▶ Starting Validation Engine (port 4005)..."
  mkdir -p "$LOG_DIR"
  cd "$SRC/pki_validation"
  POSTGRES_PASSWORD="$PG_PASS" \
  POSTGRES_PORT="5434" \
  VALIDATION_DB="pki_validation" \
  INTERNAL_API_SECRET="$INTERNAL_API_SECRET" \
  PORT="4005" \
  MIX_ENV=dev \
    mix do ecto.migrate --quiet, phx.server \
    > "$LOG_DIR/validation.log" 2>&1 &
  echo $! >> "$PID_FILE"
  echo "  PID $! → logs: $LOG_DIR/validation.log"
}

# ── Main ─────────────────────────────────────────────────────────────────────
TARGET="${1:-all}"

case "$TARGET" in
  stop)
    stop_all
    ;;
  ca-engine)
    rm -f "$PID_FILE"
    start_ca_engine
    ;;
  ca-portal)
    rm -f "$PID_FILE"
    start_ca_portal
    ;;
  ra-engine)
    rm -f "$PID_FILE"
    start_ra_engine
    ;;
  ra-portal)
    rm -f "$PID_FILE"
    start_ra_portal
    ;;
  validation)
    rm -f "$PID_FILE"
    start_validation
    ;;
  all)
    rm -f "$PID_FILE"
    start_ca_engine
    start_ca_portal
    start_ra_engine
    start_ra_portal
    start_validation
    echo ""
    echo "All services started. Tail logs with:"
    echo "  tail -f $LOG_DIR/*.log"
    echo ""
    echo "Stop all with: ./dev.sh stop"
    ;;
  *)
    echo "Unknown service: $TARGET"
    echo "Usage: $0 [all|ca-engine|ca-portal|ra-engine|ra-portal|validation|stop]"
    exit 1
    ;;
esac
