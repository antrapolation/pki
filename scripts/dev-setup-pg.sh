#!/usr/bin/env bash
# dev-setup-pg.sh — idempotent local PostgreSQL 17 setup for PKI development.
#
# Usage: ./scripts/dev-setup-pg.sh
#
# Creates the postgres superuser role and all required PKI databases
# (prod + _test variants). Safe to run multiple times.

set -euo pipefail

DATABASES=(pki_ca_engine pki_ra_engine pki_validation pki_audit_trail pki_platform)
PG_USER=postgres
PG_PASS=postgres

# ---------------------------------------------------------------------------
# 1. Detect platform and ensure postgres is installed + running
# ---------------------------------------------------------------------------

OS="$(uname -s)"

if [[ "$OS" == "Darwin" ]]; then
  if ! command -v psql &>/dev/null; then
    echo "PostgreSQL not found. Install with:"
    echo "  brew install postgresql@17 && brew link postgresql@17"
    exit 1
  fi

  # Start if not running (brew services)
  if ! pg_isready -q 2>/dev/null; then
    echo "Starting PostgreSQL via brew services..."
    brew services start postgresql@17 2>/dev/null || brew services start postgresql 2>/dev/null || true
    # Wait up to 10s
    for i in $(seq 1 10); do
      pg_isready -q && break
      sleep 1
    done
  fi

elif [[ "$OS" == "Linux" ]]; then
  if ! command -v psql &>/dev/null; then
    echo "PostgreSQL not found. Install with:"
    echo "  sudo apt-get install postgresql-17   # Debian/Ubuntu"
    echo "  sudo dnf install postgresql-server   # Fedora/RHEL"
    exit 1
  fi

  if ! pg_isready -q 2>/dev/null; then
    echo "Starting PostgreSQL via systemctl..."
    sudo systemctl start postgresql 2>/dev/null || true
    for i in $(seq 1 10); do
      pg_isready -q && break
      sleep 1
    done
  fi
fi

if ! pg_isready -q; then
  echo "ERROR: PostgreSQL is not reachable. Check installation and start it manually."
  exit 1
fi

echo "PostgreSQL is running."

# ---------------------------------------------------------------------------
# 2. Create the 'postgres' superuser role if it doesn't exist
# ---------------------------------------------------------------------------

# psql as the current user (peer auth on Linux) or via default socket (macOS)
PG_CONNECT_CMD="psql -U \"$USER\" -d postgres"
if ! $PG_CONNECT_CMD -c '\q' &>/dev/null; then
  # Try postgres user directly
  PG_CONNECT_CMD="psql -d postgres"
fi

ROLE_EXISTS=$($PG_CONNECT_CMD -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" 2>/dev/null || echo "")
if [[ -z "$ROLE_EXISTS" ]]; then
  echo "Creating role '${PG_USER}'..."
  $PG_CONNECT_CMD -c "CREATE ROLE ${PG_USER} WITH LOGIN SUPERUSER PASSWORD '${PG_PASS}';" 2>/dev/null || true
else
  echo "Role '${PG_USER}' already exists."
fi

# From here on, connect as the postgres role
PSQL="psql -U ${PG_USER} -d postgres"

# ---------------------------------------------------------------------------
# 3. Create prod + test databases
# ---------------------------------------------------------------------------

for db in "${DATABASES[@]}"; do
  for suffix in "" "_test"; do
    dbname="${db}${suffix}"
    exists=$($PSQL -tAc "SELECT 1 FROM pg_database WHERE datname='${dbname}'" 2>/dev/null || echo "")
    if [[ -z "$exists" ]]; then
      echo "Creating database '${dbname}'..."
      $PSQL -c "CREATE DATABASE ${dbname} OWNER ${PG_USER};" 2>/dev/null
    else
      echo "Database '${dbname}' already exists."
    fi
  done
done

echo ""
echo "Done. Databases available:"
$PSQL -tAc "SELECT datname FROM pg_database WHERE datname LIKE 'pki_%' ORDER BY datname;"
