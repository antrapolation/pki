# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Post-Quantum Cryptography (PQC) Certificate Authority (CA) System** being developed by Antrapolation Technology Sdn Bhd. The system manages certificate issuance primarily for PQC algorithms (targeting Malaysia's local PQC algorithm, KAZ-SIGN), while also supporting classical algorithms (RSA, ECC) for backward compatibility.

The product spec is at `docs/Product.Spec-PQC.CA.System-v1.0.docx`.

## Architecture

The system is composed of two major packages:

### Core Certificate Authority
- **CA Portal** — Web portal for system admin to manage the CA engine (user auth, user management, keystore config, key ceremony, audit logs)
- **Core CA Engine** — Main process providing entry points for CA functions. Each CA owner gets its own process with its own local user set. Supports multiple instances for fault tolerance.
- **Key Ceremony** — Handles official root key initiation with threshold scheme (Shamir-style secret sharing). Supports both software keystores and HSM keystores.
- **Issuer Key Management** — Manages sub-issuer keys (generate, update status, self-sign certs, CSR generation, certificate activation)
- **Private Key Store Management** — CRUD for keystores (software and HSM)
- **User Management** — Roles: CA Admin, Key Manager, RA Admin, Auditor (least privilege principle)

### Registration Authority
- **RA Portal** — Web portal for RA admin (CSR validation, web service config, cert profile config, CRL/LDAP/OCSP service config)
- **RA Engine** — Processes CSRs (view, verify, approve, reject). Roles: RA Admin, RA Officer, Auditor
- **Cert Profile Configuration** — Manages subject DN policy, key usage, validity policy, CRL policy, OCSP policy, notification profiles, renewal policy

## Key Design Constraints

- **Scalability**: Scale-out via adding processes to pool; can run across locations/hardware/instances
- **Availability**: Critical internal processes require >1 process registered to a group
- **Security**: All process API calls authenticated; sensitive info encrypted; private key activation passwords encrypted per-officer (not system-wide); mission-critical encryption must be digitally signed; inter-process communication authenticated and encrypted
- **PQC large output sizes**: Classical PKI workflows may not work due to bandwidth; new workflows needed
- **AI agent authentication**: System must support cryptographic authentication for AI agents (certificate issuance for AI delegates)

## Supported Certificate Types

- **KAZ-SIGN** (Malaysia local PQC algorithm)
- **ML-DSA** (NIST PQC standard)
- **RSA & ECC** (classical, for migration compatibility)
