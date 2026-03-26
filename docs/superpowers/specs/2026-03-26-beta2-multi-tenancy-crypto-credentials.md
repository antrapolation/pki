# Beta 2 Design: Multi-Tenancy + Cryptographic Credential System

**Date:** 2026-03-26
**Branch:** v1.0.0-beta.2
**Status:** Draft

---

## 1. Overview

Beta 2 transforms the PKI system from a single-tenant password-authenticated system to a multi-tenant platform with cryptographic identity and access control. Every user gets dual keypairs (signing + KEM), keypair access is controlled via a cryptographic ACL system, and each tenant is isolated in its own database with PostgreSQL schema-level module separation.

### Goals

- **Multi-tenancy**: One tenant = one CA instance = one database. Same PostgreSQL server.
- **Cryptographic credentials**: Every user has signing + KEM keypairs. No more password-only auth.
- **Keypair ACL**: Cryptographic access control for keypair activation, replacing role-based checks.
- **Three keypair protection modes**: Credential-owned, split auth token, split private key.
- **System bootstrap keypairs**: Root, sub-root, and service host keypairs created on tenant init.
- **Auditor sign-off**: Key ceremony finalization requires auditor's cryptographic signature.
- **Key Vault with signed grants**: Cryptographic grant envelopes for keypair access delegation.
- **Service-to-service crypto auth**: Replace `INTERNAL_API_SECRET` with mutual authentication via host keypairs.

---

## 2. Data Architecture

### 2.1 Database Layout

```
PostgreSQL 17 Server
│
├── pki_platform (shared)
│   ├── platform_admins
│   ├── tenants
│   └── tenant_databases
│
├── pki_tenant_{uuid} (one per tenant)
│   ├── SCHEMA ca
│   │   ├── ca.users
│   │   ├── ca.credentials
│   │   ├── ca.keypairs
│   │   ├── ca.keypair_grants
│   │   ├── ca.keystores
│   │   ├── ca.issuer_keys
│   │   ├── ca.key_ceremonies
│   │   ├── ca.issued_certificates
│   │   └── ca.system_keypairs
│   │
│   ├── SCHEMA ra
│   │   ├── ra.users
│   │   ├── ra.csr_requests
│   │   ├── ra.cert_profiles
│   │   ├── ra.api_keys
│   │   └── ra.service_configs
│   │
│   ├── SCHEMA validation
│   │   └── validation.certificate_status
│   │
│   └── SCHEMA audit
│       └── audit.events
│
├── pki_tenant_{uuid} ...
└── ...
```

### 2.2 PostgreSQL Role Isolation

Each service connects with a dedicated PostgreSQL role:

```sql
-- Per-tenant database roles
CREATE ROLE ca_role LOGIN PASSWORD '...';
CREATE ROLE ra_role LOGIN PASSWORD '...';
CREATE ROLE val_role LOGIN PASSWORD '...';
CREATE ROLE audit_role LOGIN PASSWORD '...';

-- CA role: full access to ca schema, write to validation (for notifications)
GRANT USAGE ON SCHEMA ca TO ca_role;
GRANT ALL ON ALL TABLES IN SCHEMA ca TO ca_role;
GRANT USAGE ON SCHEMA validation TO ca_role;
GRANT INSERT, UPDATE ON validation.certificate_status TO ca_role;
REVOKE ALL ON SCHEMA ra FROM ca_role;

-- RA role: full access to ra schema only
GRANT USAGE ON SCHEMA ra TO ra_role;
GRANT ALL ON ALL TABLES IN SCHEMA ra TO ra_role;
REVOKE ALL ON SCHEMA ca FROM ra_role;

-- Validation role: read-only on validation schema
GRANT USAGE ON SCHEMA validation TO val_role;
GRANT SELECT ON ALL TABLES IN SCHEMA validation TO val_role;

-- Audit role: read-only on audit schema, all modules can write
GRANT USAGE ON SCHEMA audit TO ca_role, ra_role;
GRANT INSERT ON audit.events TO ca_role, ra_role;
GRANT USAGE ON SCHEMA audit TO audit_role;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO audit_role;
```

### 2.3 Dynamic Repo (Tenant Resolution)

Ecto connects to the correct tenant database at runtime:

```elixir
# Resolve tenant from request (subdomain, session, or header)
tenant_id = resolve_tenant(conn)

# Set dynamic repo config for this request
tenant_db = "pki_tenant_#{tenant_id}"
Repo.put_dynamic_repo(%{database: tenant_db, search_path: "ca"})

# All subsequent Ecto queries go to the correct tenant + schema
```

Each service sets its `search_path` on connection:
- CA Engine: `SET search_path TO ca`
- RA Engine: `SET search_path TO ra`
- Validation: `SET search_path TO validation`
- Audit: `SET search_path TO audit`

---

## 3. Cryptographic Credential System

### 3.1 User Credential Model

Every user in the system has:

```
User
├── Profile
│   ├── username
│   ├── display_name
│   ├── role (ca_admin | key_admin | ra_admin | ra_officer | auditor)
│   ├── status (active | suspended)
│   └── password_hash (Argon2, for portal login)
│
├── Signing Credential
│   ├── public_key (stored plain)
│   ├── encrypted_private_key (encrypted with password-derived key)
│   ├── certificate (public key signed by creating admin)
│   └── algorithm (ML-DSA-65 | ECC-P256)
│
└── KEM Credential
    ├── public_key (stored plain)
    ├── encrypted_private_key (encrypted with password-derived key)
    ├── certificate (public key signed by creating admin)
    └── algorithm (ML-KEM-768 | ECDH-P256)
```

### 3.2 Authentication Flow

```
Login(username, password)
  → Verify password hash (Argon2) — fast check
  → Derive session_key from password (HKDF)
  → Decrypt signing private key with session_key — proves key ownership
  → Store session_key in encrypted session cookie
  → On logout: session_key wiped

When crypto operation needed:
  → Retrieve session_key from session
  → Decrypt relevant private key on-demand
  → Perform operation (sign, decrypt)
  → Private key not held in memory longer than needed
```

### 3.3 User Creation Flow (from diagram 1)

```
Admin creates new user:
  1. Generate signing keypair (algorithm per tenant config)
  2. Generate KEM keypair
  3. Encrypt both private keys with new user's password-derived key
  4. Admin signs new user's public keys (attestation)
  5. Create user profile with credentials
  6. Save to database
```

### 3.4 Credential Manager Module

`PkiCaEngine.CredentialManager` — internal module, not a separate service.

```elixir
# Public API
CredentialManager.create_credential(admin_session, user_attrs, password)
CredentialManager.verify_login(username, password)
CredentialManager.derive_session_key(password)
CredentialManager.decrypt_signing_key(session_key, encrypted_private_key)
CredentialManager.decrypt_kem_key(session_key, encrypted_private_key)
CredentialManager.sign(session_key, credential, data)
CredentialManager.kem_decrypt(session_key, credential, ciphertext)
CredentialManager.attest_public_key(admin_session, target_public_key)
```

---

## 4. Keypair ACL System

### 4.1 Keypair ACL Credential

The Keypair ACL is a special system credential that gates access to all operational keypairs.

```
Keypair ACL
├── Signing Keypair — signs grant envelopes
├── KEM Keypair — encrypts keypair activation passwords
└── Random password — encrypted with first CA Admin's KEM public key
```

### 4.2 Access Grant Model

When a keypair is created with credential-owned protection:

```
Keypair created:
  → Random password generated
  → Private key encrypted with random password (keystore)
  → Random password encrypted with Keypair ACL's KEM public key
  → Stored as keypair record

Granting access to a user:
  → Activate Keypair ACL (requires admin's KEM key)
  → Keypair ACL signing key constructs grant envelope:
      {keypair_id, allowed_credential_id, granted_at}
  → Keypair ACL signs the grant envelope
  → Grant stored in keypair_grants table
```

### 4.3 Two-Level Key Hierarchy

```
User wants to activate keypair:
  1. User's KEM private key (decrypted via session_key)
  2. → Decrypts Keypair ACL's random password
  3. → Activates Keypair ACL's KEM private key
  4. → Decrypts target keypair's random password
  5. → Activates target keypair's signing private key
```

---

## 5. Keypair Protection Modes

### 5.1 Credential-Owned (operational/leaf issuer keys)

```
Generate Keypair(session, :credential_own, keyspec, keyname, allowed_credentials)
  → Generate keypair
  → Generate random password, encrypt private key
  → Register with Key Vault
  → Key Vault encrypts random password with Keypair ACL's KEM public key
  → For each allowed_credential:
      → Verify credential status
      → Activate Keypair ACL signing key
      → Construct signed grant envelope
      → Store grant
  → Keypair status: 'pending'
```

### 5.2 Split Auth Token (root/sub-root keys in HSM)

```
Generate Keypair(session, {:split_auth_token, required}, keyspec, keyname, custodians)
  → Generate keypair
  → Generate random password, encrypt private key
  → Split random password via Shamir(threshold=required, shares=len(custodians))
  → For each custodian:
      → Prompt custodian for their password
      → Encrypt share with custodian's password
      → Return encrypted share to custodian (NOT stored in DB)
  → Keypair status: 'pending'
```

### 5.3 Split Private Key (software only, root/sub-root keys)

```
Generate Keypair(session, {:split_key, required}, keyspec, keyname, custodians)
  → Generate keypair
  → Split PRIVATE KEY itself via Shamir(threshold=required, shares=len(custodians))
  → For each custodian:
      → Prompt custodian for their password
      → Encrypt key share with custodian's password
      → Return encrypted share to custodian (NOT stored in DB)
  → Private key NOT stored anywhere — only exists as shares
  → Keypair status: 'pending'
```

---

## 6. Key Ceremony (Updated)

### 6.1 Ceremony Flow

```
Phase 1: Setup
  → Multiple Key Managers login (policy-driven, e.g., 2 required)
  → Auditor logs in
  → Key Manager starts ceremony with authorized session list
  → System verifies all sessions and roles
  → Returns ceremony Process ID (PID)

Phase 2: Key Generation
  → Key Manager: Generate Keypair(PID, keyspec)
  → System generates keypair, encrypts with random password
  → Keypair status = 'pending'

Phase 3: Certificate Binding
  → Either:
    a. Root Issuer: Gen SelfSign Certificate → keypair 'active'
    b. Sub Issuer: Gen CSR → keypair stays 'pending'

Phase 4: Custodian Assignment
  → Key Manager: Assign Custodians(custodians, activation_policy)
  → Split random password per activation policy
  → Each custodian provides password, receives encrypted share
  → Shares NOT stored in database

Phase 5: Finalization
  → Auditor: Finalize Key Ceremony
  → Audit trail signed by Auditor's signing key
  → Signed audit trail returned for safe keeping
  → Ceremony marked complete
```

### 6.2 Ceremony Process

The ceremony runs as a stateful GenServer process (OTP):

```elixir
# Start ceremony — returns PID
{:ok, pid} = KeyCeremonyManager.start(authorized_sessions)

# Generate keypair
{:ok, keypair_info} = KeyCeremonyManager.generate_keypair(pid, keyspec)

# Self-sign or CSR
{:ok, cert_or_csr} = KeyCeremonyManager.gen_self_sign_cert(pid, subject, profile)
# OR
{:ok, csr} = KeyCeremonyManager.gen_csr(pid, subject)

# Assign custodians
{:ok, shares} = KeyCeremonyManager.assign_custodians(pid, custodians, policy)

# Finalize (auditor)
{:ok, audit_trail} = KeyCeremonyManager.finalize(pid, auditor_session)
```

---

## 7. System Bootstrap

### 7.1 Tenant Initialization

When a new tenant is created via the Platform Portal:

```
1. Create database pki_tenant_{uuid}
2. Create PostgreSQL schemas (ca, ra, validation, audit)
3. Create PostgreSQL roles (ca_role, ra_role, val_role, audit_role)
4. Run migrations for all schemas
5. Tenant status = 'initialized' (awaiting admin setup)
```

### 7.2 First Admin Setup

When the first CA Admin visits `/setup`:

```
1. Admin provides: name, login, password, org name
2. System creates CA Admin credential:
   a. Generate signing keypair
   b. Generate KEM keypair
   c. Encrypt private keys with password-derived key
   d. Self-certify public keys (no higher authority yet)
3. System creates Keypair ACL credential:
   a. Generate signing + KEM keypairs
   b. Generate random password
   c. Encrypt private keys with random password
   d. Encrypt random password with CA Admin's KEM public key
   e. CA Admin signs Keypair ACL's public keys
   f. Grant CA Admin activation rights on Keypair ACL
4. System creates bootstrap keypairs:
   a. :root — system root signing key
   b. :sub_root — operational root signing key
   c. :strap_ca_remote_service_host_signing_key
   d. :strap_ca_remote_service_host_cipher_key
   All random passwords encrypted with CA Admin's KEM public key
5. Tenant status = 'active'
```

---

## 8. Service Architecture

### 8.1 Services

| Service | Port | Purpose |
|---------|------|---------|
| Platform Portal | 4006 | Tenant management (create, suspend, monitor) |
| CA Engine | 4001 | Core CA with Credential Manager, Key Vault, Ceremony Manager |
| CA Portal | 4002 | CA Admin GUI (tenant-scoped) |
| RA Engine | 4003 | Registration Authority REST API (tenant-scoped) |
| RA Portal | 4004 | RA Admin GUI (tenant-scoped) |
| Validation | 4005 | OCSP responder + CRL publisher (tenant-scoped) |
| PostgreSQL | 5432 | Shared database server |
| SoftHSM2 | — | PKCS#11 HSM simulator |

### 8.2 Service-to-Service Authentication

Beta.1 uses `INTERNAL_API_SECRET` (shared secret). Beta.2 replaces this with cryptographic mutual authentication:

```
CA Portal → CA Engine:
  1. Portal signs request with host signing key
  2. Engine verifies signature using Portal's public key
  3. Engine signs response
  4. Portal verifies

RA Engine → CA Engine (for CSR signing):
  1. RA signs request with host signing key
  2. CA verifies, processes, signs response
```

Host keypairs are created during tenant bootstrap and distributed to services via the platform configuration.

### 8.3 Tenant Resolution

```
Request flow:
  Browser → Caddy → Portal/Engine
    → Extract tenant from: subdomain | session | API key
    → Look up tenant in pki_platform.tenants
    → Set dynamic Ecto repo to pki_tenant_{uuid}
    → Set search_path per service role
    → Process request
```

---

## 9. Platform Portal

### 9.1 Features

- **Tenant CRUD**: Create, list, suspend, activate tenants
- **Database provisioning**: Auto-create DB, schemas, roles, run migrations
- **Platform admin management**: Super-admin accounts (separate from tenant users)
- **Tenant health dashboard**: DB size, user count, certificate count per tenant
- **On-prem mode**: Auto-provisions single default tenant, portal can be disabled

### 9.2 Tenant Creation Flow

```
Platform admin clicks "Create Tenant":
  1. Enter: org name, admin email, subdomain
  2. System:
     a. Generate tenant UUID
     b. CREATE DATABASE pki_tenant_{uuid}
     c. Create schemas + roles + permissions
     d. Run all migrations
     e. Insert tenant record in pki_platform.tenants
     f. Return setup URL for tenant admin
  3. Tenant admin visits setup URL → bootstrap flow (Section 7.2)
```

---

## 10. Migration from Beta.1

### 10.1 Breaking Changes

- Database structure completely different (multi-tenant + schemas)
- User model changes (dual keypairs added)
- API authentication changes (crypto mutual auth)
- Key ceremony flow changes (multi-manager + auditor)
- Shares no longer stored in DB

### 10.2 Migration Strategy

Beta.2 is a fresh deployment — no data migration from beta.1. The beta.1 tag (`v1.0.0-beta.1`) preserves the old system. Beta testers start fresh on beta.2.

---

## 11. New Elixir Modules

### CA Engine

```
PkiCaEngine.CredentialManager     — user credential lifecycle
PkiCaEngine.CredentialManager.Signing  — signing operations
PkiCaEngine.CredentialManager.Kem      — KEM operations
PkiCaEngine.KeyVault              — keypair registration + grant management
PkiCaEngine.KeyCeremonyManager    — stateful ceremony process
PkiCaEngine.KeypairACL            — ACL credential management
PkiCaEngine.SystemKeypairs        — bootstrap keypair management
PkiCaEngine.TenantRepo            — dynamic Ecto repo for tenant resolution
```

### Platform

```
PkiPlatform.TenantManager         — tenant CRUD + DB provisioning
PkiPlatform.Repo                  — Ecto repo for pki_platform DB
PkiPlatform.DatabaseProvisioner   — create DB, schemas, roles, migrate
```

### Shared

```
PkiTenancy.Resolver               — tenant resolution from request context
PkiTenancy.DynamicRepo            — dynamic repo configuration per tenant
```

---

## 12. Algorithm Support (Protocol-Based)

### 12.1 Supported Algorithms

| Purpose | PQC Algorithm | Classical Fallback |
|---------|--------------|-------------------|
| Signing | ML-DSA-65 (FIPS 204) | ECC-P256 |
| KEM | ML-KEM-768 (FIPS 203) | ECDH-P256 |
| Hash | SHA-3-256 | SHA-256 |
| Symmetric | AES-256-GCM | AES-256-GCM |
| Key Derivation | HKDF-SHA-256 | HKDF-SHA-256 |

Algorithm choice is configurable per tenant. Default: PQC.

### 12.2 PkiCrypto Library (New Shared Library)

A new `pki_crypto` library provides protocol-based algorithm dispatch. All services depend on it.

```
src/pki_crypto/
├── lib/pki_crypto/
│   ├── algorithm.ex              — protocol definition
│   ├── signing/
│   │   ├── rsa4096.ex            — RSA-4096 implementation
│   │   ├── ecc_p256.ex           — ECC-P256 implementation
│   │   ├── ecc_p384.ex           — ECC-P384 implementation
│   │   └── ml_dsa_65.ex          — ML-DSA-65 implementation (liboqs NIF)
│   ├── kem/
│   │   ├── ecdh_p256.ex          — ECDH-P256 implementation
│   │   └── ml_kem_768.ex         — ML-KEM-768 implementation (liboqs NIF)
│   ├── symmetric.ex              — AES-256-GCM (shared, not protocol-based)
│   ├── kdf.ex                    — HKDF-SHA-256 (shared, not protocol-based)
│   └── registry.ex               — algorithm name ↔ struct lookup
└── mix.exs
```

### 12.3 Protocol Definition

```elixir
defprotocol PkiCrypto.Algorithm do
  @doc "Generate a keypair for this algorithm"
  def generate_keypair(algorithm)

  @doc "Sign data with a private key"
  def sign(algorithm, private_key, data)

  @doc "Verify a signature"
  def verify(algorithm, public_key, signature, data)

  @doc "KEM encapsulate — generate shared secret + ciphertext from public key"
  def kem_encapsulate(algorithm, public_key)

  @doc "KEM decapsulate — recover shared secret from ciphertext + private key"
  def kem_decapsulate(algorithm, private_key, ciphertext)

  @doc "Algorithm identifier string (for DB storage and wire format)"
  def identifier(algorithm)

  @doc "Algorithm type — :signing, :kem, or :dual"
  def algorithm_type(algorithm)
end
```

### 12.4 Algorithm Implementations

Each algorithm is a struct + protocol implementation:

```elixir
# Signing algorithm
defmodule PkiCrypto.Signing.RSA4096 do
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.RSA4096 do
  def generate_keypair(_), do: # Erlang :public_key
  def sign(_, private_key, data), do: # :public_key.sign
  def verify(_, public_key, sig, data), do: # :public_key.verify
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "RSA-4096"
  def algorithm_type(_), do: :signing
end

# KEM algorithm
defmodule PkiCrypto.Kem.ECDHP256 do
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Kem.ECDHP256 do
  def generate_keypair(_), do: # Erlang :crypto.generate_key(:ecdh, :secp256r1)
  def sign(_, _, _), do: {:error, :not_supported}
  def verify(_, _, _, _), do: {:error, :not_supported}
  def kem_encapsulate(_, public_key), do: # ECDH + HKDF
  def kem_decapsulate(_, private_key, ct), do: # ECDH + HKDF
  def identifier(_), do: "ECDH-P256"
  def algorithm_type(_), do: :kem
end
```

### 12.5 Algorithm Registry

Lookup algorithms by name (from DB or API):

```elixir
defmodule PkiCrypto.Registry do
  @algorithms %{
    "RSA-4096"    => %PkiCrypto.Signing.RSA4096{},
    "ECC-P256"    => %PkiCrypto.Signing.ECCP256{},
    "ML-DSA-65"   => %PkiCrypto.Signing.MLDSA65{},
    "KAZ-SIGN"    => %PkiCrypto.Signing.KazSign{},
    "ECDH-P256"   => %PkiCrypto.Kem.ECDHP256{},
    "ML-KEM-768"  => %PkiCrypto.Kem.MLKEM768{},
  }

  def get(name), do: Map.get(@algorithms, name)
  def signing_algorithms, do: # filter by algorithm_type == :signing
  def kem_algorithms, do: # filter by algorithm_type == :kem
  def all, do: @algorithms
end
```

### 12.6 Usage

```elixir
# Tenant config stores algorithm names as strings
tenant_signing_algo = PkiCrypto.Registry.get(tenant.signing_algorithm)
tenant_kem_algo = PkiCrypto.Registry.get(tenant.kem_algorithm)

# All operations dispatch via protocol — zero knowledge of specific algorithm
{:ok, keypair} = PkiCrypto.Algorithm.generate_keypair(tenant_signing_algo)
{:ok, sig} = PkiCrypto.Algorithm.sign(tenant_signing_algo, private_key, data)
{:ok, {shared_secret, ct}} = PkiCrypto.Algorithm.kem_encapsulate(tenant_kem_algo, public_key)
```

### 12.7 Adding a New Algorithm

To add a new PQC algorithm (e.g., SLH-DSA):

1. Create `lib/pki_crypto/signing/slh_dsa.ex` with struct + `defimpl`
2. Register in `PkiCrypto.Registry`
3. Add to ceremony form dropdown in portal

Zero changes to core engine, ceremony, signing, or validation code.

### 12.8 Replacing CryptoAdapter

The existing `PkiCaEngine.KeyCeremony.CryptoAdapter` protocol is replaced by `PkiCrypto.Algorithm`. The `CryptoAdapter` also handles Shamir secret sharing which is not algorithm-specific — that moves to a standalone module:

```elixir
# Shamir is not an algorithm — it's a utility
PkiCrypto.Shamir.split(secret, k, n)
PkiCrypto.Shamir.recover(shares)
```

### 12.9 Formalize CaClient Behaviour

The duck-typed RA→CA client gets an explicit behaviour:

```elixir
defmodule PkiRaEngine.CaClient do
  @callback sign_certificate(csr_pem :: String.t(), cert_profile :: map()) ::
              {:ok, map()} | {:error, term()}
end
```

`DefaultCaClient` and `HttpCaClient` both add `@behaviour PkiRaEngine.CaClient` and `@impl true`.

---

## 13. Environment Configuration

All secrets and infrastructure credentials are stored in `.env` files, never hardcoded. Separate files per environment:

```
.env.dev          — local development defaults
.env.test         — CI/test environment
.env.prod         — production (never committed to git)
```

### .env contents

```ini
# PostgreSQL (platform database)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=<generated>

# PostgreSQL roles (per-schema isolation)
CA_DB_PASSWORD=<generated>
RA_DB_PASSWORD=<generated>
VAL_DB_PASSWORD=<generated>
AUDIT_DB_PASSWORD=<generated>

# Session signing
SECRET_KEY_BASE=<generated-64-bytes>

# Service-to-service (used during bootstrap, replaced by crypto auth after tenant init)
INTERNAL_API_SECRET=<generated-32-bytes>

# SoftHSM2
SOFTHSM_TOKEN_LABEL=PkiCA
SOFTHSM_SO_PIN=<generated>
SOFTHSM_USER_PIN=<generated>

# Platform admin (first platform superadmin)
PLATFORM_ADMIN_USERNAME=<set-by-operator>
PLATFORM_ADMIN_PASSWORD=<set-by-operator>
```

### Per-environment behavior

| Secret | Development | Test | Production |
|--------|------------|------|------------|
| DB passwords | `postgres` / simple defaults | `test_*` prefixed | Strong generated values |
| SECRET_KEY_BASE | Fixed dev value | Fixed test value | `openssl rand -base64 64` |
| INTERNAL_API_SECRET | `dev-secret` | `test-secret` | `openssl rand -base64 32` |
| HSM PINs | `1234` / `12345678` | Same as dev | Strong generated values |
| Platform admin | `admin` / `admin` | N/A | Operator-chosen |

### Loading

Services read from `.env` via `env_file:` in compose.yml (containers) or `Config.Reader` in runtime.exs (bare metal). The `.env` file is in `.gitignore` — only `.env.example` is committed.

---

## 14. Security Properties

| Property | How |
|----------|-----|
| Tenant data isolation | Separate database per tenant |
| Module table isolation | PostgreSQL schemas + role grants |
| User credential isolation | Private keys encrypted per-user password |
| Keypair access control | Cryptographic grants via Keypair ACL |
| Service authentication | Mutual crypto auth via host keypairs |
| Key ceremony integrity | Multi-manager + auditor sign-off |
| Share confidentiality | Shares held by custodians, not in DB |
| Audit integrity | Hash-chain audit trail, auditor-signed |
| Session security | Password-derived key in encrypted cookie |

---

## 15. Development Practices

### 15.1 Test-Driven Development (TDD)

All beta.2 code must follow TDD — write failing tests before implementation.

**Cycle per feature:**
1. **Red** — Write a test for the expected behaviour. Run it. It must fail.
2. **Green** — Write the minimum code to make the test pass.
3. **Refactor** — Clean up while keeping tests green.

**Test layers:**
| Layer | What | Framework |
|-------|------|-----------|
| Unit | Individual modules (CredentialManager, KeyVault, Algorithm impls) | ExUnit |
| Integration | Cross-module flows (bootstrap → credential → ceremony) | ExUnit with real DB |
| E2E | Browser + API (tenant creation → login → ceremony → signing) | Playwright |

**Requirements:**
- Every public function has at least one test
- Every error path has a test (not just happy path)
- Crypto operations tested with known test vectors where available
- Protocol implementations tested via shared test suite (one test module, all impls must pass)

### 15.2 SOLID Principles (Adapted for Elixir)

| Principle | Elixir Interpretation | Application in Beta.2 |
|-----------|----------------------|----------------------|
| **S** — Single Responsibility | Each module does one thing. One reason to change. | `CredentialManager` handles credentials, not ceremonies. `KeyVault` handles grants, not key generation. |
| **O** — Open/Closed | Open for extension via protocols, closed for modification. | `PkiCrypto.Algorithm` protocol — add algorithms without changing core. New tenant DB schemas without modifying existing ones. |
| **L** — Liskov Substitution | All protocol implementations are interchangeable. | Any `PkiCrypto.Algorithm` impl (RSA, ECC, ML-DSA) works anywhere an algorithm is expected. Mock clients substitute for Http clients without behaviour change. |
| **I** — Interface Segregation | Small, focused protocols and behaviours. | `PkiCrypto.Algorithm` has only the methods algorithms need. Portal client behaviours don't force engines to implement portal-specific concerns. |
| **D** — Dependency Inversion | Depend on protocols/behaviours, not concrete modules. | Engine depends on `PkiCrypto.Algorithm` protocol, not `RSA4096` module. Portal depends on `CaEngineClient` behaviour, not `Http` module. Tenant repo resolved at runtime, not compiled in. |

### 15.3 Code Organization Rules

- **Max module size**: ~300 lines. If larger, split by responsibility.
- **Max function size**: ~20 lines. Extract helpers for clarity.
- **No God modules**: A module that "does everything" must be decomposed.
- **Explicit dependencies**: `alias` at the top, no deep nested module references.
- **No side effects in pure functions**: Separate computation from I/O (DB, network, crypto).
- **Context boundaries**: Each context (Credential, Ceremony, Vault) has a single public API module that delegates to private implementation modules.
