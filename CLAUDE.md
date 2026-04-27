# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Post-Quantum Cryptography (PQC) Certificate Authority (CA) System** being developed by Antrapolation Technology Sdn Bhd. The system manages certificate issuance primarily for PQC algorithms (targeting Malaysia's local PQC algorithm, KAZ-SIGN), while also supporting classical algorithms (RSA, ECC) for backward compatibility.

The product spec is at `docs/Product.Spec-PQC.CA.System-v1.0.docx`.

## Architecture

The system runs two tiers of BEAM nodes:

**Platform tier (1 node):** `pki_platform` handles tenant lifecycle (provision, deprovision, :peer-spawn per-tenant BEAM), platform user management, and platform audit trail. Backed by PostgreSQL. Caddy routes `admin.*` to this node on port 4006.

**Tenant tier (one node per tenant):** Each tenant gets a dedicated `pki_tenant` BEAM node containing:
- **CA portal** — Phoenix LiveView UI for CA admin, key manager, auditor roles
- **CA engine** — key ceremony, issuer key management, certificate signing (in-process, no HTTP API)
- **RA portal** — Phoenix LiveView UI for RA admin, officer, auditor roles
- **RA engine** — CSR processing, certificate profile config (in-process, no HTTP API)
- **pki_validation** — OCSP responder + CRL publisher (in-process, served from tenant subdomain)
- **Mnesia** — local disc_copies storage for all CA/RA/validation state

Portals call engines directly (in-process function calls), not via HTTP. PostgreSQL is never touched by tenant nodes — all tenant state is in Mnesia.

### Supported Certificate Types
- **KAZ-SIGN** (Malaysia local PQC algorithm)
- **ML-DSA** (NIST PQC standard)
- **SLH-DSA** (NIST PQC hash-based)
- **RSA & ECC** (classical, for migration compatibility)

## Key Design Constraints

- **Scalability**: Scale-out via adding processes to pool; can run across locations/hardware/instances
- **Availability**: Critical internal processes require >1 process registered to a group
- **Security**: All process API calls authenticated; sensitive info encrypted; private key activation passwords encrypted per-officer (not system-wide); mission-critical encryption must be digitally signed; inter-process communication authenticated and encrypted
- **PQC large output sizes**: Classical PKI workflows may not work due to bandwidth; new workflows needed
- **AI agent authentication**: System must support cryptographic authentication for AI agents (certificate issuance for AI delegates)
