# Phase A: Per-Tenant BEAM + Mnesia — Design Spec

**Date:** 2026-04-16
**Goal:** Replace the shared-BEAM schema-per-tenant PostgreSQL architecture with per-tenant BEAM nodes using Mnesia for CA/RA/Validation data. Each tenant gets full process-level isolation. Platform keeps PostgreSQL for tenant registry and audit.
**Duration:** ~4 weeks of focused work.
**Prerequisite:** Existing code preserved on `legacy/ecto-based` branch before any rewrite begins.

---

## 1. Architecture Overview

Two release types built from the same umbrella:

### Platform release (`pki_platform`)
- **Apps:** `pki_platform_engine`, `pki_platform_portal`
- **Storage:** PostgreSQL (`pki_platform` database)
- **Responsibilities:** tenant registry, platform users, platform audit trail, tenant lifecycle (spawn/stop/monitor tenant nodes via `peer` module)
- **Port:** 4006 (platform portal)

### Tenant release (`pki_tenant`)
- **Apps:** `pki_ca_engine`, `pki_ra_engine`, `pki_validation`, `pki_tenant_web`, `pki_tenant`, `pki_mnesia`, `pki_crypto`
- **Storage:** Mnesia (local to `/var/lib/pki/tenants/<slug>/mnesia/`)
- **Responsibilities:** all CA + RA + Validation functions for one tenant
- **Port:** one dynamically assigned port per tenant (host-based routing dispatches CA vs RA)
- **Communication:** distributed Erlang to platform node for audit event delivery

### What changes from today
- `pki_ca_portal` + `pki_ra_portal` → merged into `pki_tenant_web` with host-based dispatch
- All Ecto schemas in CA/RA/Validation → Mnesia struct tables
- `pki_platform_engine` keeps PostgreSQL (Ecto stays for platform only)
- `PkiPlatformEngine.TenantSupervisor` → replaced by `PkiPlatformEngine.TenantLifecycle` using `peer` module

### What stays unchanged
- `pki_crypto` — pure crypto library, no storage
- Cross-algo signing logic (`X509Builder`, `Asn1`, `Csr`, `AlgorithmRegistry`)
- KAZ-SIGN + ML-DSA NIFs (`pki_oqs_nif`)

---

## 2. Mnesia Data Model

All records are Elixir structs stored in Mnesia tables. Each tenant node creates tables on first boot.

### CA Engine tables

| Table | Struct | Type | Purpose |
|-------|--------|------|---------|
| `ca_instances` | `%CaInstance{}` | `disc_copies` | CA hierarchy (root, sub-CAs) |
| `issuer_keys` | `%IssuerKey{}` | `disc_copies` | Key records with `ceremony_mode` (:full / :simplified) |
| `key_ceremonies` | `%KeyCeremony{}` | `disc_copies` | Ceremony state tracking |
| `ceremony_participants` | `%CeremonyParticipant{}` | `disc_copies` | Custodians + auditors (name, role, identity verification) |
| `ceremony_transcripts` | `%CeremonyTranscript{}` | `disc_copies` | Serialized event log for PDF generation |
| `threshold_shares` | `%ThresholdShare{}` | `disc_copies` | Custodian name + password hash + encrypted share (NOT user FK) |
| `issued_certificates` | `%IssuedCertificate{}` | `disc_only_copies` | Signed certificates (can grow large) |

#### Key struct fields

```elixir
%IssuerKey{
  id: binary,
  key_alias: String.t(),
  algorithm: String.t(),
  status: String.t(),           # pending | active | suspended | retired | archived
  is_root: boolean,
  ceremony_mode: atom,          # :full | :simplified
  keystore_ref: binary,
  certificate_der: binary | nil,
  certificate_pem: String.t() | nil,
  threshold_config: map         # %{k: 2, n: 3}
}

%CeremonyParticipant{
  id: binary,
  ceremony_id: binary,
  name: String.t(),             # entered during ceremony, not a user account
  role: atom,                   # :custodian | :auditor
  identity_verified_by: String.t() | nil,   # auditor's name
  identity_verified_at: DateTime.t() | nil,
  share_accepted_at: DateTime.t() | nil
}

%ThresholdShare{
  id: binary,
  issuer_key_id: binary,
  custodian_name: String.t(),   # string, NOT FK to portal_users
  share_index: integer,
  encrypted_share: binary,
  password_hash: binary,
  min_shares: integer,
  total_shares: integer
}

%CeremonyTranscript{
  id: binary,
  ceremony_id: binary,
  entries: [map],               # list of %{timestamp, actor, action, details}
  finalized_at: DateTime.t() | nil
}
```

### RA Engine tables

| Table | Struct | Type | Purpose |
|-------|--------|------|---------|
| `ra_instances` | `%RaInstance{}` | `disc_copies` | RA instance records |
| `ra_ca_connections` | `%RaCaConnection{}` | `disc_copies` | Links to CA issuer keys |
| `cert_profiles` | `%CertProfile{}` | `disc_copies` | Certificate profile config |
| `csr_requests` | `%CsrRequest{}` | `disc_only_copies` | CSR submissions (can grow) |
| `api_keys` | `%ApiKey{}` | `disc_copies` | External API access |
| `dcv_challenges` | `%DcvChallenge{}` | `disc_copies` | Domain control validation |

### Validation tables

| Table | Struct | Type | Purpose |
|-------|--------|------|---------|
| `certificate_status` | `%CertificateStatus{}` | `disc_only_copies` | Revocation status for OCSP |

**Simplification:** `signing_key_config` table is eliminated. OCSP responder and CRL publisher call `KeyActivation.get_active_key(issuer_key_id)` directly — signing key and issuer key are in the same process.

### Tenant portal users

| Table | Struct | Type | Purpose |
|-------|--------|------|---------|
| `portal_users` | `%PortalUser{}` | `disc_copies` | Per-tenant portal users (not platform users) |

```elixir
%PortalUser{
  id: binary,
  username: String.t(),
  password_hash: binary,
  display_name: String.t(),
  email: String.t(),
  role: atom,                   # :ca_admin | :key_manager | :ra_admin | :ra_officer | :auditor
  status: String.t()
}
```

Portal users live in tenant's Mnesia. Platform has its own `platform_users` in PostgreSQL for super-admins.

---

## 3. Tenant Node Structure

### Supervision tree

```
PkiTenant.Application
├── PkiTenant.Mnesia.Bootstrap         # creates/opens tables on boot
├── PkiTenant.AuditBridge              # GenServer, forwards audit to platform via dist Erlang
├── PkiCaEngine.Supervisor
│   ├── PkiCaEngine.KeyActivation      # threshold reconstruction, in-memory active keys
│   └── PkiCaEngine.CeremonyWatchdog   # local to this tenant's tables only
├── PkiRaEngine.Supervisor
│   ├── PkiRaEngine.CsrProcessor       # auto-forward approved CSRs to CA signing
│   └── PkiRaEngine.DcvPoller          # expire stale DCV challenges
├── PkiValidation.Supervisor
│   ├── PkiValidation.OcspResponder    # signs via KeyActivation.get_active_key
│   └── PkiValidation.CrlPublisher     # same
├── PkiTenantWeb.Endpoint              # single Phoenix endpoint, one port
└── PkiTenant.TaskSupervisor            # async work (CSR signing, webhook delivery)
```

### Boot sequence

1. `peer` starts the BEAM with env vars: `TENANT_ID`, `TENANT_SLUG`, `TENANT_PORT`, `MNESIA_DIR`, `PLATFORM_NODE`
2. `PkiTenant.Application.start/2` reads env, configures the port
3. `Mnesia.Bootstrap` opens Mnesia directory — creates tables if first boot, loads existing otherwise
4. `AuditBridge` connects to platform node via `Node.connect`
5. Engine supervisors start GenServers (KeyActivation starts empty — requires custodian unlock)
6. Phoenix endpoint starts on assigned port
7. AuditBridge sends `{:tenant_ready, tenant_id}` to platform

### Config injection

No config files per tenant. Platform passes everything via env vars in the `peer` call:

- `TENANT_ID` — UUID
- `TENANT_SLUG` — human-readable slug for subdomain routing
- `TENANT_PORT` — dynamically assigned from pool
- `MNESIA_DIR` — `/var/lib/pki/tenants/<slug>/mnesia/`
- `PLATFORM_NODE` — `pki_platform@127.0.0.1`
- `RELEASE_COOKIE` — shared Erlang cookie for distributed cluster

---

## 4. Platform Node Structure

### Supervision tree

```
PkiPlatform.Application
├── PkiPlatform.Repo                     # Ecto + PostgreSQL
├── PkiPlatform.TenantLifecycle          # GenServer — spawn/stop/monitor tenant peers
├── PkiPlatform.AuditReceiver            # GenServer — receives audit casts from tenants, batch-writes to PG
├── PkiPlatform.TenantHealthMonitor      # periodic :erpc.call health check every 30s
├── PkiPlatform.PortAllocator            # assigns ports 5001..5999, persists to PG
├── PkiPlatform.CaddyConfigurator        # dynamic Caddy config via admin API
├── PkiPlatformPortalWeb.Endpoint        # platform admin portal on port 4006
└── PkiPlatform.TaskSupervisor
```

### TenantLifecycle — core orchestrator

```elixir
TenantLifecycle.create_tenant(attrs)      # insert PG → allocate port → spawn peer → wait :tenant_ready → configure Caddy
TenantLifecycle.stop_tenant(tenant_id)    # graceful :peer.stop → release port → remove Caddy route
TenantLifecycle.restart_tenant(tenant_id) # stop + start
TenantLifecycle.list_tenants()            # registry with status (running/stopped/error)
```

State: `%{tenant_id => %{peer_pid: pid, node: atom, port: integer, status: atom}}`. Monitors each peer pid — on crash, auto-restarts with backoff.

### AuditReceiver

Receives `GenServer.cast` from tenant AuditBridge. Batches events and bulk-inserts to PostgreSQL every 100ms or 50 events, whichever comes first. Fire-and-forget on tenant side — signing path is never blocked by audit writes.

### PortAllocator

Pool: 5001–5999 (supports ~1000 tenants per host). Persists assignments in `tenant_port_assignments` PostgreSQL table so ports survive platform restart.

### CaddyConfigurator

Updates Caddy via JSON admin API (`POST localhost:2019/config/...`) when tenants start/stop. Caddy handles TLS cert provisioning per subdomain automatically. No file reload.

### Platform boot sequence

1. PostgreSQL connection established
2. PortAllocator loads existing assignments from PG
3. TenantLifecycle queries `tenants` table for all active tenants
4. For each: allocate/reuse port → spawn peer → wait for `:tenant_ready`
5. CaddyConfigurator registers routes for each started tenant
6. Platform portal starts on port 4006
7. TenantHealthMonitor begins periodic checks

---

## 5. Web Layer — Host-Based Routing

### Tenant endpoint

Each tenant runs one `PkiTenantWeb.Endpoint` on one port. Requests dispatched by hostname.

### Host router

```elixir
defmodule PkiTenantWeb.HostRouter do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case extract_service(conn.host) do
      :ca -> PkiTenantWeb.CaRouter.call(conn, PkiTenantWeb.CaRouter.init([]))
      :ra -> PkiTenantWeb.RaRouter.call(conn, PkiTenantWeb.RaRouter.init([]))
      _   -> conn |> send_resp(404, "Unknown service") |> halt()
    end
  end

  defp extract_service(host) do
    case host |> String.split(".") do
      [_slug, "ca" | _] -> :ca
      [_slug, "ra" | _] -> :ra
      _                  -> :unknown
    end
  end
end
```

### Directory structure

```
lib/pki_tenant_web/
├── ca/
│   ├── live/               # IssuerKeysLive, CeremonyLive, etc.
│   ├── controllers/
│   └── components/
├── ra/
│   ├── live/               # CsrsLive, CertProfilesLive, etc.
│   ├── controllers/
│   └── components/
├── shared/
│   └── components/         # shared UI components
├── host_router.ex
├── ca_router.ex
├── ra_router.ex
└── endpoint.ex
```

### Assets

Each service gets its own CSS/JS entry point (`ca/app.js`, `ra/app.js`) sharing a common base. One esbuild + tailwind build, two bundles. Phoenix serves the right bundle based on which router handled the request.

### Local dev

```bash
TENANT_SLUG=dev TENANT_PORT=4000 iex -S mix phx.server
```
Access via `dev.ca.localhost:4000` and `dev.ra.localhost:4000` (using `/etc/hosts` entries or `lvh.me` which resolves to 127.0.0.1).

---

## 6. Inter-Node Communication

All communication over distributed Erlang. Three patterns:

### 6a. Audit events (tenant → platform)

Tenant's `AuditBridge` calls `GenServer.cast` to platform's `AuditReceiver`. Fire-and-forget so the signing path is never blocked. AuditBridge keeps a small local buffer (last 1000 events in a `:queue`) and flushes when connection restores if platform was temporarily unreachable.

### 6b. Tenant lifecycle (platform → tenant)

- Spawn: `:peer.start_link/1` with env vars
- Monitor: `Process.monitor(peer_pid)` — platform gets `{:DOWN, ...}` on crash
- Health check: `:erpc.call(tenant_node, PkiTenant.Health, :check, [], 5000)`
- Stop: `:peer.stop(peer_pid)`

### 6c. CA signing (RA → CA, same tenant node)

No inter-node call. Both engines run in the same tenant BEAM. The existing `Direct` client pattern stays literally direct — genuinely in-process, no schema-prefix gymnastics.

### 6d. Tenant registration handshake

1. Platform spawns peer via `:peer.start_link`
2. Tenant boots Mnesia, engines, Phoenix
3. AuditBridge connects to platform node, sends `{:tenant_ready, tenant_id}`
4. Platform marks tenant healthy, configures Caddy route
5. Platform begins periodic health checks via `:erpc.call`

### What this replaces

| Current | New |
|---------|-----|
| `RaEngineClient.Direct` (cross-app in shared BEAM) | Same module, genuinely in-process |
| `CaEngineClient.Direct` (cross-app in shared BEAM) | Same module, genuinely in-process |
| `PlatformAudit.log/2` (direct PG write) | `AuditBridge.log/2` (cast to platform) |
| `TenantRepo.ca_repo(tenant_id)` schema prefix | Gone. One Mnesia per tenant, no prefix |
| `SigningKeyStore` GenServer | Gone. `KeyActivation.get_active_key` serves OCSP directly |

---

## 7. Migration Strategy

### Step 1: Preserve existing code

```bash
git checkout -b legacy/ecto-based
git push origin legacy/ecto-based
git checkout main
```

### Step 2: New umbrella structure

| Remove | Replaced by |
|--------|-------------|
| `pki_ca_portal` | `pki_tenant_web` (ca/ namespace) |
| `pki_ra_portal` | `pki_tenant_web` (ra/ namespace) |
| `pki_ca_engine` | `pki_ca_engine` (rewritten, Mnesia) |
| `pki_ra_engine` | `pki_ra_engine` (rewritten, Mnesia) |
| `pki_validation` | `pki_validation` (rewritten, Mnesia) |
| `pki_platform_portal` | stays (PostgreSQL, unchanged) |
| `pki_platform_engine` | rewritten (lifecycle, audit receiver, port allocator) |

| Keep unchanged | Reason |
|----------------|--------|
| `pki_crypto` | Pure crypto, no storage |
| `pki_oqs_nif` | NIF wrapper, no storage |

| New apps | Purpose |
|----------|---------|
| `pki_tenant` | Application, Mnesia bootstrap, AuditBridge, Health |
| `pki_tenant_web` | Phoenix endpoint, host router, CA + RA LiveViews |
| `pki_mnesia` | Shared struct definitions, table helpers, query utilities |

### Step 3: Build order

Each step produces testable, working software:

1. **`pki_mnesia`** — struct definitions + table creation helpers. Tested via `mnesia:table_info` assertions.
2. **`pki_ca_engine` rewrite** — ceremonies, issuer keys, certificate signing, key activation. Against Mnesia.
3. **`pki_ra_engine` rewrite** — CSR validation, cert profiles, API keys, DCV. Against Mnesia.
4. **`pki_validation` rewrite** — OCSP responder + CRL publisher using `KeyActivation.get_active_key`.
5. **`pki_tenant` + `pki_tenant_web`** — boot sequence, host router, LiveViews migrated.
6. **`pki_platform_engine` rewrite** — TenantLifecycle, AuditReceiver, PortAllocator, CaddyConfigurator.
7. **Integration test** — platform spawns tenant, full ceremony + CSR + sign + OCSP, audit in platform PG.

### Step 4: Data migration (existing VPS tenants)

One-time for comp-4 and comp-5:

1. Export from PostgreSQL via `psql` queries → JSON per table
2. `Mix.Task` reads export, inserts into fresh Mnesia instance
3. Verify: key counts, ceremony state, issued cert counts match
4. Cut over: stop old release, start new platform + tenant releases

### Testing strategy

Each Mnesia test gets a unique temporary directory, starts Mnesia there, creates tables, runs test, cleans up. Zero interference between parallel tests.

```
cd src/pki_mnesia && mix test           # struct + table definitions
cd src/pki_ca_engine && mix test        # ceremony, signing, key mgmt
cd src/pki_ra_engine && mix test        # CSR, profiles, API keys
cd src/pki_validation && mix test       # OCSP, CRL
cd src/pki_platform_engine && mix test  # spawns real tenant peers
mix test test/integration/              # full end-to-end
```

---

## 8. Success Criteria

After Phase A lands:

- [ ] Platform node spawns and manages 5+ tenant nodes on current VPS
- [ ] Each tenant node boots with its own Mnesia directory, creates tables on first run
- [ ] Full key ceremony flow works end-to-end in a tenant node (including new ceremony redesign: single session, custodian names not user accounts, auditor identity verification, printable transcript)
- [ ] Root CA requires full ceremony; sub-CA supports both full and simplified modes
- [ ] CSR submission → verify → approve → sign → issued certificate works in tenant node
- [ ] OCSP responder signs responses using `KeyActivation.get_active_key` (no separate SigningKeyStore)
- [ ] Host-based routing: `<slug>.ca.domain` and `<slug>.ra.domain` both resolve to the same tenant port
- [ ] Audit events from tenant nodes appear in platform's PostgreSQL audit table
- [ ] Platform health monitor detects tenant crash and auto-restarts
- [ ] Caddy routes are dynamically added/removed when tenants start/stop
- [ ] All PQC algorithms (KAZ-SIGN-128/192/256, ML-DSA-44/65/87) work in the new architecture
- [ ] Cross-algorithm signing matrix (classical↔PQC, cross-family PQC) unchanged — all 4 combos work
- [ ] Existing comp-4 and comp-5 data migrated and verified

## 9. Out of Scope (deferred to later phases)

- Multi-host distribution (Phase B)
- Per-tenant Mnesia backup to object storage (Phase C)
- Hot code upgrades (Phase C)
- BYOK-HSM / PKCS#11 (Phase D)
- Key ceremony UI redesign (separate phase, after Phase A data model is solid)
- Metrics/Prometheus endpoint
- Rate limiting on RA API
- Production hardening items (CI, sops, rollback) — adapted separately for new architecture
