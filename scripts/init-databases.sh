#!/bin/bash
# Creates all required databases for PKI services
# Executed by Postgres container on first start via /docker-entrypoint-initdb.d/

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE pki_ca_engine;
    CREATE DATABASE pki_ra_engine;
    CREATE DATABASE pki_validation;
    CREATE DATABASE pki_audit_trail;
    CREATE DATABASE pki_platform;
EOSQL

echo "PKI databases created: pki_ca_engine, pki_ra_engine, pki_validation, pki_audit_trail, pki_platform"
