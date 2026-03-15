# PQC Certificate Authority System — Design Specification

**Version:** 1.0
**Date:** 2026-03-15
**Status:** Draft
**Product Spec Reference:** `docs/Product.Spec-PQC.CA.System-v1.0.docx`

## 1. Overview

A Post-Quantum Cryptography (PQC) Certificate Authority system built on Elixir/Erlang OTP, targeting Malaysia's sovereign PQC algorithm (KAZ-SIGN) while supporting NIST PQC standards (ML-DSA, SLH-DSA) and classical algorithms (RSA, ECC). Deployable as SaaS (multi-tenant) or on-premises (single-tenant) from the same codebase.

### 1.1 Goals (v1)

- Issue KAZ-SIGN, ML-DSA certificates (per product spec goals)
- Issue SLH-DSA certificates (added beyond product spec — already supported by `ap_java_crypto`, low incremental cost)
- Issue RSA & ECC certificates (classical compatibility)
- Key ceremony with threshold scheme (Shamir Secret Sharing)
- Synchronous ceremony (root CA) and asynchronous ceremony (sub-CA)
- Full RA workflow: CSR submission, validation, approval, signing
- OCSP, CRL, and LDAP validation services
- Tamper-evident audit trail
- Inter-node authentication via SSDID (Self-Sovereign Distributed Identity)
- External protocols: REST API, CMP (RFC 4210), OCSP (RFC 6960), CRL (RFC 5280)

### 1.2 Out of Scope (v1)

- Client API for certificate usage
- AI agent enrollment workflow (design for, implement later)
- Notification service (cert expiry, renewal reminders)
- ACME, EST, SCEP protocols (future)

### 1.3 Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Elixir/Erlang OTP | Distributed by design, fault tolerant, hot code upgrades |
| Web framework | Phoenix LiveView | Real-time UI for ceremonies, all-BEAM stack, simplified deployment |
| Repo strategy | Separate repos per service | Security isolation (CA code separate from RA), independent release cadence |
| Process isolation | Each service as its own Erlang node | Maximum security, physical isolation possible, fault containment |
| Database | Hybrid — Postgres + Mnesia/ETS | Postgres for durable data, Mnesia for hot cache and distributed state |
| Inter-node comm | Erlang Distribution (internal) + REST/gRPC (external) | Native BEAM performance internally, standard APIs for integrations |
| Inter-node auth | SSDID (W3C DID 1.1) | Mutual auth via challenge-response, PQC algorithm support, decentralized |
| User auth | SSDID credentials | DID-based identity, no centralized password store |
| Key ceremony | Sync + async modes, configurable per CA | Sync for compliance (root CA), async for operational flexibility (sub-CA) |
| Deployment | SaaS-first, deployable on-prem | Same codebase, different configuration |

## 2. System Architecture

### 2.1 Repo Tiers

#### Tier 1 — Core Libraries

Stable, versioned, tagged releases. Consumed by all services.

| Repo | Status | Purpose |
|------|--------|---------|
| `ex_ccrypto` | Existing | Crypto primitives — RSA, ECC, ciphers, digest, KDF, MAC, X.509 cert/CSR generation |
| `x509` | Existing | X.509 certificate operations, templates, extensions, CRL, PEM/DER encoding |
| `keyx` | Existing | Shamir Secret Sharing (HashiCorp Vault-compatible) |
| `strap_ciphagile` | Existing | Algorithm-agile binary serialization (TSLV encoding) |
| `strap_proc_reg` | Existing | Distributed process registry, service discovery, heartbeat, load balancing (ETS-backed) |
| `pki_audit_trail` | **New** | Tamper-evident audit logging library. Hash-chained events, append-only. |

#### Tier 2 — Provider Libraries

Moderate release cadence. Follows core lib versions.

| Repo | Status | Purpose |
|------|--------|---------|
| `StrapPrivateKeystore` | Existing | Protocol — keystore interface contract |
| `StrapSoftPrivateKeystore` | Existing | Software keystore implementation (RSA, ECC, ML-DSA, SLH-DSA, KAZ-SIGN/KEM) |
| `strap_priv_key_store_provider` | Existing | Unified provider API — routes to any backend, supports remote/distributed access |
| `strap_soft_priv_key_store_provider` | Existing | GenServer provider — software keys |
| `strap_java_crypto_priv_key_store_provider` | Existing | GenServer provider — PQC via BouncyCastle/JRuby |
| `strap_softhsm_priv_key_store_provider` | Existing | GenServer provider — HSM via PKCS#11 Rust NIF |
| `ap_java_crypto` | Existing | Java bridge for PQC algorithms (ML-DSA, SLH-DSA, ML-KEM, KAZ-SIGN, KAZ-KEM) |
| `ex_jruby_port` | Existing | Generic Elixir-to-Java/JRuby port bridge |

#### Tier 3 — Service Applications

Independent repos, each producing its own Erlang node release.

| Repo | Spec Type | Purpose |
|------|-----------|---------|
| `pki_ca_portal` | Web Portal | Phoenix LiveView — CA admin GUI |
| `pki_ca_engine` | Process | Core CA — signing, key ceremony, key management |
| `pki_ra_portal` | Web Portal | Phoenix LiveView — RA admin GUI |
| `pki_ra_engine` | Process + Library | RA — CSR processing, cert profiles, service config |
| `pki_validation` | Process (New) | OCSP responder, CRL publisher, LDAP directory |

#### External Dependency — SSDID

| Component | Purpose |
|-----------|---------|
| `ssdid_server` + `ssdid_client` | Inter-node mutual auth via DID challenge-response |
| `ssdid_vault` + `ssdid_verifier` | Node key management + DID resolution/verification |
| `ssdid_registry` | Distributed DID Document storage (Mnesia-backed) |
| `ssdid_transport` | HTTP, Erlang RPC, and Local transport adapters |

### 2.2 Service Node Architecture

```
External Clients (Browser, AI Agents, CMP Clients, OCSP Clients)
                    │
                    ▼
          API Gateway / Load Balancer
          (TLS termination, rate limiting)
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
  pki_ca_portal  pki_ra_portal  pki_ra_engine ◄── REST/CMP (external)
  (LiveView)     (LiveView)     (RA Engine)
        │           │           │
        └─────SSDID/RPC────────┘
                    │
                    ▼
              pki_ca_engine ◄── Only node with signing keys
              (CA Engine, ISOLATED)
                    │
                    ▼
              pki_validation ◄── OCSP/CRL/LDAP (external)
              (read-only, scalable)
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   PostgreSQL    Mnesia       HSM/SoftHSM
   (durable)    (hot cache)   (private keys)
```

### 2.3 Inter-Node Communication

- **Internal (cluster):** Erlang Distribution with TLS encryption via `inet_tls_dist` (OTP built-in). All inter-node traffic encrypted and mutually authenticated at the transport layer. On top of TLS, SSDID provides application-layer mutual authentication — each node bootstraps with its own DID identity and verifies peers via challenge-response before accepting requests. `strap_proc_reg` handles service discovery, group routing, and load balancing.
- **External (clients):** REST API (custom JSON/HTTPS) and CMP (RFC 4210) for certificate enrollment. OCSP (RFC 6960) and CRL (RFC 5280) for certificate validation. All external endpoints terminate TLS at the API gateway or directly.

### 2.4 Process Pooling & High Availability

Per the product spec NFRs on scalability and availability:

**Process pooling:** Each service can run multiple instances registered to a `strap_proc_reg` group. New instances can be added to the pool dynamically — on the same hardware, different hardware, or different locations. `strap_proc_reg` group selectors (random, sequential) handle routing across pool members.

**Critical process availability:** The following processes are classified as critical and must maintain >1 instance registered to a group:

| Process | Min Instances | Failover Strategy |
|---------|--------------|-------------------|
| pki_ca_engine | 2 (primary + standby) | Mnesia replicates activation state metadata (handle refs, session config). On primary DOWN, standby is available but signing keys require custodian re-activation (K-of-N shares). For HSM-backed keys, standby can resume immediately if HSM is network-accessible. |
| pki_ra_engine | 2+ | Stateless request routing via `strap_proc_reg`. Any instance handles any request. |
| pki_validation | 2+ | Fully stateless (Mnesia cache). Load balanced. Any instance serves any query. |
| SSDID Registry | 2+ | Mnesia cluster replication. Any node resolves DIDs. |

**Supervision strategy:** Each service uses OTP supervision trees with `:one_for_one` strategy for independent processes and `:rest_for_one` for dependent process chains (e.g., CA engine depends on keystore provider). Supervisors restart failed processes automatically. Node-level failure detected via Erlang node monitoring (nodeup/nodedown events from `strap_proc_reg`).

## 3. Service Details

### 3.1 pki_ca_portal (Web Portal)

Phoenix LiveView application. CA admin GUI.

**Functions:**
- User authentication via SSDID
- User management UI (CA Admin, Key Manager, RA Admin, Auditor)
- Private keystore configuration UI (software/HSM CRUD)
- Key ceremony UI (real-time participant tracking, share distribution)
- Audit log viewer
- CA engine management (start/stop, status monitoring)

**First-run bootstrap:** If the system is not yet initialized (no CA instance exists), the portal immediately redirects to a root CA admin initialization wizard. The first CA Admin is bootstrapped by providing a DID credential — this initial admin must be pre-registered in the SSDID Registry before first login. The bootstrap flow creates the first `ca_instance` and `ca_user` (CA Admin role).

**No own database.** Reads/writes through `pki_ca_engine` via SSDID-authenticated RPC.

### 3.2 pki_ca_engine (Process)

Core CA engine. One Erlang node per CA owner. The only node with access to signing keys.

**Process modules (per spec):**

| Module | Spec Type | Responsibility |
|--------|-----------|----------------|
| Core CA Engine | Process | Main entry point. Spin up/shutdown on admin login. Multiple instances for fault tolerance. |
| Key Ceremony | Process | Root key initiation. Threshold scheme (Shamir SSS via KeyX). Sync and async modes. Self-signed root cert or CSR for external root. |
| Issuer Key Management | Process | Sub-issuer key CRUD. Generate, update status, self-sign certs, generate CSR, activate by uploading cert. Activated by key custodian (threshold). |
| Private Key Store Management | Process | Keystore CRUD. Dynamic search for activated keystores. Software activated by default. Key Manager selects and configures. |
| Configure Keypair Access | Process | Bind private keys to authorized users. Access control matrix. Activated by Key Manager. |
| User Management | Process | Local users per CA instance. Roles: CA Admin, Key Manager, RA Admin, Auditor. Least privilege. Activated by CA Admin. |

**User roles:**
- **CA Admin** — Manage CA admin users, manage Auditor users
- **Key Manager** — Manage other Key Managers, keystore config, key lifecycle, private key access
- **RA Admin** — Manage other RA admins, assign private key access to RA officers
- **Auditor** — View audit log, participate in Key Ceremony

**Security constraints:**
- Only accepts requests from authenticated RA/Portal nodes (SSDID mutual auth)
- Private key material never leaves this node (or HSM)
- Signing key active only after threshold activation, with configurable timeout

### 3.3 pki_ra_portal (Web Portal)

Phoenix LiveView application. RA admin GUI.

**Functions:**
- User authentication via SSDID
- User management UI (RA Admin, RA Officer, Auditor)
- CSR validation UI (view, verify, approve, reject)
- Web service configuration UI
- Cert profile configuration UI
- CA engine configuration UI

**No own database.** Reads/writes through `pki_ra_engine` via SSDID-authenticated RPC.

### 3.4 pki_ra_engine (Process + Library)

Registration Authority engine. CSR processing, policy enforcement, service configuration.

**Process modules (per spec):**

| Module | Spec Type | Responsibility |
|--------|-----------|----------------|
| RA User Management | Process | Local users per RA. Roles: RA Admin, RA Officer. CRUD by RA Admin. Note: Auditor CRUD is managed by CA Admin (per product spec), not RA Admin — requires cross-service RPC from CA engine. |
| CSR Validation Module | Process | View, verify, approve, reject CSRs. Core RA workflow. |

**Library modules (per spec):**

| Module | Spec Type | Responsibility |
|--------|-----------|----------------|
| Web Services Configuration | Library | CSR web service API CRUD — port, rate limiting, IP whitelist/blacklist, connection security |
| CRL Services Configuration | Library | CRL service CRUD — port, URL, credentials |
| LDAP Services Configuration | Library | LDAP service CRUD — port, URL, credentials |
| OCSP Services Configuration | Library | OCSP service CRUD — port, URL, credentials |
| Cert Profile Configuration | Library | Full cert profile CRUD — subject DN policy, issuer policy, key usage, ext key usage, validity, CRL, OCSP, renewal, notification profiles, cert publish policy |
| CA Engine Configuration | Library | CA engine node CRUD — connection parameters |

**RA user roles:**
- **RA Admin** — Manage RA admins and RA officers
- **RA Officer** — Process CSRs (view, verify, approve, reject)
- **Auditor** — View audit log

**External protocols:**
- REST API (custom) — CSR submission, cert retrieval, status queries
- CMP (RFC 4210) — Certificate enrollment and revocation

### 3.5 pki_validation (New)

Validation services. Runs the runtime services that RA library modules configure. Read-only, horizontally scalable.

| Service | Protocol | Data Source |
|---------|----------|-------------|
| OCSP Responder | RFC 6960 | Mnesia cache (hot) + Postgres issued_certificates (cold) |
| CRL Publisher | RFC 5280 | Postgres revocation data, published per CRL update period |
| LDAP Directory | LDAP | Cert publish per cert profile policy |

**No signing keys.** Reads certificate status from Mnesia (replicated from CA) and Postgres.

### 3.6 pki_audit_trail (New — Tier 1 Library)

Tamper-evident audit logging. Consumed by all services.

**Design:**
- Hash-chained events: each event includes `prev_hash`, creating a tamper-evident chain
- `event_hash = SHA3-256(event_id || timestamp || node_name || actor_did || action || resource_type || resource_id || details || prev_hash)`
- Append-only Postgres table
- Mnesia write-ahead buffer for reliability (disc_only_copies, flushed to Postgres async)
- All services call `pki_audit_trail.log(action, resource, details)` for every operation

**Audited actions include:** ceremony_started, ceremony_completed, key_generated, key_activated, key_suspended, csr_submitted, csr_verified, csr_approved, csr_rejected, certificate_issued, certificate_revoked, user_created, user_updated, user_deleted, keystore_configured, keypair_access_granted, keypair_access_revoked, login, logout.

## 4. Data Model

### 4.1 PostgreSQL — Persistent Data

**Database isolation:** Each service tier has its own database.

#### pki_ca_engine database

| Table | Key Fields | Purpose |
|-------|------------|---------|
| `ca_instances` | id, name, status, domain_info, created_at, created_by | One row per CA owner |
| `issuer_keys` | id, ca_instance_id, key_alias, algorithm, status (pending/active/suspended/archived), keystore_ref, is_root, threshold_config | Root + sub-issuer keys. Private key material in keystore, NOT in DB. |
| `keystores` | id, ca_instance_id, type (software/hsm), config (encrypted), status, provider_name | Keystore config — references to soft/HSM providers |
| `keypair_access` | id, issuer_key_id, user_id, granted_by, granted_at | Key-to-user access binding |
| `ca_users` | id, ca_instance_id, did, display_name, role, status, created_at | Local users per CA instance. DID-based identity. |
| `threshold_shares` | id, issuer_key_id, custodian_user_id, share_index, encrypted_share, min_shares, total_shares | Shamir SSS shares — encrypted per custodian password |
| `issued_certificates` | id, serial_number, issuer_key_id, subject_dn, cert_der, cert_pem, not_before, not_after, status (active/revoked), revoked_at, revocation_reason, cert_profile_id | All certificates issued by this CA |
| `key_ceremonies` | id, ca_instance_id, issuer_key_id, ceremony_type (sync/async), status, initiated_by, participants (jsonb), started_at, completed_at, window_expires_at | Ceremony records |

#### pki_ra_engine database

| Table | Key Fields | Purpose |
|-------|------------|---------|
| `cert_profiles` | id, name, subject_dn_policy (jsonb: mandatory_fields), issuer_policy (jsonb: issuer_key_ref, issuer_public_url, key_rotation_policy), key_usage, ext_key_usage, digest_algo, validity_policy (jsonb: validity_period, validity_start, validity_end), timestamping_policy (jsonb: timestamping_url, timestamping_server, sync_period), crl_policy (jsonb: crl_update_period, crl_dist_point, crl_publishing_config, issuer_policy), ocsp_policy (jsonb: ocsp_url, issuer_policy), ca_repository_url, issuer_url, included_extensions (jsonb), renewal_policy (jsonb: key_reuse, csr_reuse, allowed_renewal_lead_time), notification_profile (jsonb: notification_type, notification_config, notification_frequency, notification_start — stored for future use, delivery mechanism out of scope v1), cert_publish_policy (jsonb: cert_repos_config, ca_repository_url) | Full cert profile per spec — all fields from product spec represented |
| `csr_requests` | id, csr_der, csr_pem, subject_dn, cert_profile_id, status (pending/verified/approved/rejected/issued), submitted_at, reviewed_by, reviewed_at, rejection_reason, issued_cert_serial | CSR lifecycle tracking |
| `ra_users` | id, did, display_name, role (ra_admin/ra_officer/auditor), status, created_at | RA-local users. Separate from CA users per spec. |
| `service_configs` | id, service_type (csr_web/crl/ldap/ocsp), port, url, rate_limit, ip_whitelist (jsonb), ip_blacklist (jsonb), connection_security, credentials (encrypted), ca_engine_ref | Unified config for all RA library service types |
| `ra_api_keys` | id, hashed_key, ra_user_id, label, expiry, rate_limit, status (active/revoked), created_at, revoked_at | API keys for external REST client authentication. Keys hashed with SHA3-256. Managed by RA Admin via portal. |

#### Audit database (shared)

| Table | Key Fields | Purpose |
|-------|------------|---------|
| `audit_events` | id, event_id (UUID), timestamp, node_name, actor_did, actor_role, action, resource_type, resource_id, details (jsonb), prev_hash, event_hash | Hash-chained tamper-evident audit log. Append-only. |

### 4.2 Mnesia — Distributed Hot Cache

| Table | Storage Type | Purpose |
|-------|-------------|---------|
| `strap_proc_reg` | disc_copies | Service registry — survives restarts, syncs across cluster |
| SSDID sessions | ram_copies | Active sessions, challenge state — ephemeral, speed critical |
| OCSP response cache | ram_copies | Cached OCSP responses with TTL — rebuilt from Postgres on restart |
| Issued cert cache | disc_copies | Hot cert data — fast reads, replicated to validation nodes |
| Audit event buffer | disc_only_copies | Write-ahead buffer — flush to Postgres async |
| CA engine state | disc_copies | Active key handles, ceremony progress — failover to standby |

**Design principle:** Mnesia holds hot/reconstructable state. If a node restarts, it rebuilds from Postgres + re-registers with `strap_proc_reg`. No data loss on restart.

### 4.3 Portals — No Database

`pki_ca_portal` and `pki_ra_portal` have no own database. They operate through their respective engines via SSDID-authenticated RPC.

## 5. Key Ceremony Workflow

### 5.1 Synchronous Ceremony (Root CA)

All key custodians must be present simultaneously.

1. **CA Admin initiates** — specifies algorithm (KAZ-SIGN/ML-DSA/RSA/ECC), keystore (soft/HSM), threshold config (K-of-N), domain info. Pre-check: at least one keystore configured.
2. **Participants join** — Multiple Key Managers + at least 1 Auditor authenticate via SSDID. LiveView shows real-time participant list.
3. **Root keypair generated** — via provider (soft/HSM/Java PQC). Private key in memory only.
4. **Threshold share distribution** — secret split into N shares via KeyX (Shamir SSS). Each custodian enters personal password. Share encrypted with password (Argon2 + AES-256-GCM). Encrypted share stored in `threshold_shares`. Raw share wiped from memory.
5. **Certificate generation** — two paths:
   - **Path A (Independent Root):** Self-signed root cert generated → registered → key marked active → sub-CA keypair + cert generated → sub-CA marked active.
   - **Path B (Sub-CA):** CSR generated → registered → key marked pending → CSR signed by external CA → admin uploads cert → key marked active.
6. **Ceremony completed** — private key material wiped from memory. Ceremony record finalized.

### 5.2 Asynchronous Ceremony (Sub-CA)

Custodians join independently within a time window.

1. **Initiation** — CA Admin creates ceremony with time window (e.g., 24 hours). Keypair generated, shares prepared. Custodians notified out-of-band.
2. **Share collection** — each custodian logs in independently, authenticates via SSDID, enters personal password. Share encrypted and stored. LiveView shows progress ("3 of 5 custodians completed"). Private key material held encrypted in CA engine memory.
3. **Completion** — all N custodians complete → certificate generated (Path A or B). Key material wiped. OR window expires → ceremony fails, key material destroyed.

**Security:** During async ceremony, private key material is held encrypted in CA engine memory (never in DB). The in-memory key material is sealed with an AES-256-GCM session key derived from partial shares collected so far — as each custodian provides their share, the session key is re-derived. This means even a memory dump cannot recover the private key without the custodian passwords.

- **Crash:** Ceremony must be restarted from scratch. No key material persists — the encrypted in-memory state is lost with the process.
- **Graceful shutdown:** If the CA node is intentionally stopped during an async ceremony window, the ceremony is marked as failed, key material is explicitly zeroed, and all collected encrypted shares are retained in `threshold_shares` for a new ceremony attempt.
- **Window expiry:** Timer fires, key material destroyed, ceremony marked failed. Custodians must re-initiate.

### 5.3 Day-to-Day Key Activation

1. K custodians authenticate and provide shares (each enters password → share decrypted)
2. Threshold met → secret reconstructed (software: private key via KeyX; HSM: activation password)
3. Key loaded into provider GenServer state. Available for RA signing requests.
4. Configurable session timeout. Key wiped on timeout or explicit deactivation.
5. Key activation state (handle reference, session metadata, timeout config) replicated via Mnesia to standby CA node. **Note:** Raw private key material is NOT replicated — the standby node must independently activate the key by collecting K shares from custodians if the primary fails. For HSM-backed keys, only the HSM slot reference is replicated since the HSM itself handles key persistence.

## 6. Certificate Issuance Flow

### 6.1 CSR Submission → Signing → Delivery

1. **CSR Submitted** — via REST API or CMP (RFC 4210) to `pki_ra_engine`. Authenticated via API key or SSDID credential. Stored in `csr_requests` table, status: pending.
2. **Automatic Validation** — CSR Validation Module checks: signature verification, subject DN policy (matches cert profile), key algorithm (allowed by profile), rate limit and IP check (per Web Services Config). Pass → status: verified. Fail → status: rejected with reason.
3. **RA Officer Review** — officer views verified CSR in `pki_ra_portal` LiveView. Reviews subject details, usage, requester identity. Approves (selects cert profile) or rejects (with reason). Audit logged.
4. **Certificate Signing** — RA engine sends approved CSR + cert profile to CA engine via SSDID-authenticated RPC. CA engine: verifies RA node identity, verifies issuer key is active (threshold-activated), applies cert profile extensions (key usage, validity, CRL/OCSP/issuer URLs), signs certificate with issuer's private key (soft/HSM/PQC), assigns serial number, returns signed cert (DER + PEM).
5. **Storage & Replication** — cert written to CA Postgres (`issued_certificates`), Mnesia hot cache (replicated to validation nodes), RA Postgres (`csr_requests` status → issued).
6. **Delivery** — REST API response (PEM/DER/PKCS7), CMP response (ip/cp message per RFC 4210), LDAP publish (per cert publish policy).

### 6.2 Certificate Revocation

1. **Revocation request** — via RA Portal (officer) or REST/CMP API. Reason: keyCompromise, cessationOfOperation, affiliationChanged, etc.
2. **RA approval** — RA Officer reviews and approves revocation.
3. **CA updates status** — `issued_certificates` status → revoked. `revoked_at` + `revocation_reason` set. Mnesia replicates to validation nodes.
4. **Validation updated** — OCSP responder returns "revoked". CRL regenerated per CRL update period. LDAP entry updated.

## 7. Supported Algorithms

### 7.1 Post-Quantum (via `ap_java_crypto` + BouncyCastle/KAZ)

| Algorithm | Variants | Type | Standard |
|-----------|----------|------|----------|
| KAZ-SIGN | 128, 192, 256 | Signing | Malaysia sovereign PQC |
| ML-DSA | 44, 65, 87 | Signing | NIST FIPS 204 (Dilithium) |
| SLH-DSA | SHA2/SHAKE variants | Signing | NIST FIPS 205 (SPHINCS+) |
| KAZ-KEM | 128, 192, 256 | Key Encapsulation | Malaysia sovereign PQC |
| ML-KEM | 512, 768, 1024 | Key Encapsulation | NIST FIPS 203 (Kyber) |

### 7.2 Classical (via `ex_ccrypto` + Erlang/OTP crypto)

| Algorithm | Variants | Type |
|-----------|----------|------|
| RSA | 2048, 4096, 8192 | Signing + Encryption |
| ECC | P-256, P-384, P-521, Ed25519, Ed448 | Signing |

### 7.3 Crypto-Agility

Cert profiles specify the algorithm. CA engine dispatches to the right provider:
- PQC → `strap_java_crypto_priv_key_store_provider`
- Classical (software) → `strap_soft_priv_key_store_provider`
- HSM-backed → `strap_softhsm_priv_key_store_provider`

Adding new algorithms = new provider implementation, no CA/RA code changes.

## 8. Deployment

### 8.1 On-Premises Topologies

**Minimal (single server):** All 5 nodes on one machine, different ports. Single Postgres. Software keystore. Use case: dev, testing, small org.

**Standard (3+ servers):** CA engine isolated on dedicated server with HSM. RA + portals on app server(s). Validation nodes horizontally scaled. Postgres with streaming replication. Use case: government, enterprise.

**High Security (full isolation):** Every service on dedicated hardware. Network segmentation: CA Zone, Portal Zone, RA Zone, DMZ (validation), Audit Zone. HSM cluster. Air-gapped root CA ceremony machine. Use case: national CA, sovereign PKI, defense.

### 8.2 SaaS (Multi-Tenant)

**Tenant isolation:** Each tenant gets dedicated `pki_ca_engine` node + CA database + own SSDID identity + own keystore config.

**Shared services:** RA engine pool (tenant_id routing via `strap_proc_reg`), validation pool, portal instances (tenant context via auth), SSDID Registry cluster.

**Scaling:** CA = 1 node per tenant. RA/Portal/Validation = horizontal pool scaling. Postgres = primary-replica per tier with read replicas.

### 8.3 Erlang Distributed Features

| Feature | Usage |
|---------|-------|
| Mnesia replication | Hot cache sync across cluster (certs, sessions, registry) |
| Node monitoring | nodeup/nodedown for failover detection |
| Process monitoring | DOWN messages trigger supervisor restarts |
| `strap_proc_reg` | Service discovery, group routing, load balancing |
| Hot code upgrades | Update validation/RA nodes without downtime |
| SSDID over `:rpc` | Mutual auth on Erlang distribution channel |

### 8.4 Release & Packaging

- **Elixir Releases:** Self-contained tarballs with embedded ERTS per service. No runtime deps on target.
- **Docker Images:** One image per service. Compose file for minimal setup.
- **Kubernetes:** Helm chart for production SaaS deployment.
- **Configuration:** Runtime config via env vars (`config/runtime.exs`). Deployment mode (saas/onprem), cluster topology, Postgres URLs, HSM config, SSDID registry URL.
- **Release signing:** All release artifacts (tarballs, Docker images) are digitally signed. Tarballs signed with GPG. Docker images signed via cosign. Helm charts include provenance metadata. Per product spec NFR: "Mission critical but difficult to deploy encryption must be digitally signed."

## 9. External Protocol Support

### 9.1 v1 Protocols

| Protocol | Standard | Service | Purpose |
|----------|----------|---------|---------|
| REST API | Custom JSON/HTTPS | pki_ra_engine | CSR submission, cert retrieval, status queries, management |
| CMP | RFC 4210 | pki_ra_engine | Certificate enrollment, revocation |
| OCSP | RFC 6960 | pki_validation | Certificate status queries |
| CRL | RFC 5280 | pki_validation | Certificate revocation lists |

### 9.2 Future Protocols

| Protocol | Standard | Priority |
|----------|----------|----------|
| ACME | RFC 8555 | Medium — automated enrollment for DevOps |
| EST | RFC 7030 | Medium — modern SCEP replacement |
| SCEP | Draft | Low — legacy device enrollment |

## 10. External API Authentication

External clients (non-BEAM, non-cluster) authenticate to `pki_ra_engine` REST and CMP endpoints via:

- **SSDID Verifiable Credential:** Preferred method. Client presents a VC issued during SSDID registration. RA engine verifies the VC proof via `ssdid_verifier`. Supports PQC signature algorithms.
- **API Key:** For legacy/simple integrations. API keys are issued by RA Admin via the RA Portal, stored as hashed values in `ra_api_keys` table (added to RA database), with configurable expiry and rate limits. Keys can be rotated and revoked.
- **CMP shared secret:** For CMP protocol specifically, per RFC 4210 Section 4.4. Used for initial registration; subsequent requests use signature-based authentication.

## 11. Error Handling & Failure Recovery

### 11.1 Supervision Strategy

See Section 2.4 for supervision tree design and process pooling configuration.

### 11.2 Critical Failure Modes

| Failure | Impact | Recovery |
|---------|--------|----------|
| CA engine unreachable during signing | RA receives `{:error, :ca_unavailable}` | CSR remains in `csr_requests` with status `approved`. RA engine runs a periodic retry process that re-attempts signing for all approved-but-unissued CSRs. `strap_proc_reg` detects DOWN, routes to standby if available. |
| Mnesia replication lag | Validation nodes serve stale OCSP/CRL data | Acceptable for short periods (OCSP responses have TTL). Mnesia anti-entropy syncs on reconnect. |
| Ceremony partially completes, custodian unavailable | Async: ceremony continues within window. Sync: ceremony fails. | Async: remaining custodians complete within window. If window expires, ceremony fails and must restart. |
| Postgres unreachable | Writes fail, reads fall back to Mnesia cache | Mnesia audit buffer holds events. Services continue operating from Mnesia state. Postgres writes retry on reconnect. |
| Node crash during key activation | Active key lost from GenServer state | Standby CA node notified via nodedown. Custodians must re-activate on standby (or primary when it recovers). HSM keys persist in hardware. |

### 11.3 Circuit Breakers

Inter-node RPC calls use circuit breaker pattern: if a target node fails N consecutive requests, the circuit opens and requests fail fast for a cooldown period before retrying. Prevents cascade failures across the cluster.

## 12. Security Model

- **Private keys** never leave `pki_ca_engine` node (or HSM). No other node has signing key access.
- **Threshold activation** required for all signing keys. No single person can activate.
- **SSDID mutual authentication** on all inter-node communication. Both parties verify identity.
- **Per-officer encryption** for threshold shares. System has no blanket access to activation passwords.
- **Hash-chained audit trail** — tamper-evident, append-only, all actions logged.
- **Database isolation** — CA, RA, and Audit databases are separate.
- **Network segmentation** supported — CA zone, RA zone, DMZ for validation.
- **All API calls authenticated** — external via API key or SSDID credential, internal via SSDID.
- **Sensitive data encrypted** — keystore configs, credentials, threshold shares encrypted at rest.
- **Inter-node encryption** — Erlang Distribution uses TLS via `inet_tls_dist`. All inter-process communication authenticated and encrypted per product spec NFR.
- **Release artifact signing** — all deployment artifacts digitally signed per product spec NFR.

## 13. References

- Product Specification: `docs/Product.Spec-PQC.CA.System-v1.0.docx`
- SSDID System: `~/Workspace/SSDID/` (Self-Sovereign Distributed Identity)
- SSDID SDK: `~/Workspace/ssdid-sdk/` (Rust SDK for mobile wallet integration)
- NIST FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 203 (ML-KEM)
- RFC 4210 (CMP), RFC 5280 (X.509/CRL), RFC 6960 (OCSP)
- W3C DID 1.1, W3C Verifiable Credentials Data Model
