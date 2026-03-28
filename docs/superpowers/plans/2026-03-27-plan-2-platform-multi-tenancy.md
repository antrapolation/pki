# Platform + Multi-Tenancy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add multi-tenancy infrastructure — a platform database for tenant registry, dynamic Ecto repos for per-tenant database routing, a database provisioner that creates tenant databases with PostgreSQL schema isolation, and a Platform Portal for tenant management.

**Architecture:** One shared `pki_platform` database stores tenant metadata. Each tenant gets its own database (`pki_tenant_{uuid}`) with 4 PostgreSQL schemas (ca, ra, validation, audit) and dedicated roles. A `PkiTenancy` shared library provides tenant resolution and dynamic repo management used by all services. The Platform Portal is a new Phoenix LiveView app on port 4006.

**Tech Stack:** Elixir, Ecto (dynamic repos), PostgreSQL 17 (schemas + roles), Phoenix LiveView, Tailwind + daisyUI

**Spec:** `docs/superpowers/specs/2026-03-26-beta2-multi-tenancy-crypto-credentials.md` Sections 2, 7, 8, 9

**Depends on:** Plan 1 (pki_crypto) — completed

---

## File Structure

```
src/pki_tenancy/                    — shared tenancy library
├── mix.exs
├── lib/pki_tenancy/
│   ├── tenant.ex                   — tenant schema (for pki_platform DB)
│   ├── platform_repo.ex            — Ecto repo for pki_platform DB
│   ├── tenant_repo.ex              — dynamic Ecto repo for tenant DBs
│   ├── resolver.ex                 — resolve tenant from request context
│   ├── provisioner.ex              — create tenant DB, schemas, roles, migrate
│   └── migrator.ex                 — run migrations on a specific tenant DB
└── test/

src/pki_platform_portal/            — new Phoenix app (port 4006)
├── mix.exs
├── lib/pki_platform_portal/
│   └── application.ex
├── lib/pki_platform_portal_web/
│   ├── router.ex
│   ├── controllers/
│   │   ├── session_controller.ex   — platform admin login
│   │   └── session_html/
│   ├── live/
│   │   ├── dashboard_live.ex       — tenant overview
│   │   └── tenants_live.ex         — tenant CRUD
│   └── components/
│       └── layouts.ex
├── config/
└── assets/
```

---

### Task 1: Create pki_tenancy shared library

**Files:**
- Create: `src/pki_tenancy/mix.exs`
- Create: `src/pki_tenancy/lib/pki_tenancy.ex`
- Create: `src/pki_tenancy/test/test_helper.exs`

- [ ] **Step 1: Create directory structure**
- [ ] **Step 2: Write mix.exs** with deps: `ecto_sql`, `postgrex`, `jason`, `uniq`
- [ ] **Step 3: Write root module**
- [ ] **Step 4: Write test helper** with Ecto sandbox setup
- [ ] **Step 5: Verify compilation**
- [ ] **Step 6: Commit**

---

### Task 2: Create PlatformRepo and Tenant schema

**Files:**
- Create: `src/pki_tenancy/lib/pki_tenancy/platform_repo.ex`
- Create: `src/pki_tenancy/lib/pki_tenancy/tenant.ex`
- Create: `src/pki_tenancy/priv/repo/migrations/20260327000001_create_tenants.exs`
- Create: `src/pki_tenancy/config/config.exs`
- Create: `src/pki_tenancy/config/dev.exs`
- Create: `src/pki_tenancy/config/test.exs`
- Test: `src/pki_tenancy/test/pki_tenancy/tenant_test.exs`

Tenant schema:
```elixir
schema "tenants" do
  field :name, :string           # org name
  field :slug, :string           # subdomain slug
  field :database_name, :string  # pki_tenant_{uuid}
  field :status, :string         # initialized | active | suspended
  field :signing_algorithm, :string, default: "ECC-P256"
  field :kem_algorithm, :string, default: "ECDH-P256"
  field :metadata, :map, default: %{}
  timestamps()
end
```

- [ ] **Step 1: Write failing tests** — tenant CRUD, validation, uniqueness
- [ ] **Step 2: Write PlatformRepo** — standard Ecto.Repo
- [ ] **Step 3: Write Tenant schema + changeset** with UUIDv7 PK
- [ ] **Step 4: Write migration**
- [ ] **Step 5: Write configs** — database: pki_platform, port: 5434
- [ ] **Step 6: Run tests**
- [ ] **Step 7: Commit**

---

### Task 3: Create TenantRepo (dynamic per-tenant database routing)

**Files:**
- Create: `src/pki_tenancy/lib/pki_tenancy/tenant_repo.ex`
- Test: `src/pki_tenancy/test/pki_tenancy/tenant_repo_test.exs`

TenantRepo dynamically connects to the correct tenant database:

```elixir
defmodule PkiTenancy.TenantRepo do
  use Ecto.Repo, otp_app: :pki_tenancy, adapter: Ecto.Adapters.Postgres

  @doc "Execute a function in the context of a specific tenant database."
  def with_tenant(tenant_or_db_name, schema_prefix, fun) do
    # Temporarily configure this repo to point to the tenant's database
    # and set search_path to the given schema
  end
end
```

The key mechanism: `Ecto.Repo.put_dynamic_repo/1` or configuring the repo at runtime via `Ecto.Repo.config/0` override.

Actually, the simpler approach for Ecto: use `Ecto.Repo` with `prefix:` option on queries:
```elixir
Repo.all(User, prefix: "ca")  # queries ca.users table
```

And switch databases by starting a dynamic repo with different config per request.

- [ ] **Step 1: Write failing tests** — connect to tenant DB, set schema prefix, execute query
- [ ] **Step 2: Implement TenantRepo** with dynamic database switching
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

### Task 4: Create Database Provisioner

**Files:**
- Create: `src/pki_tenancy/lib/pki_tenancy/provisioner.ex`
- Test: `src/pki_tenancy/test/pki_tenancy/provisioner_test.exs`

Provisioner creates a new tenant:
1. Generate tenant UUID
2. `CREATE DATABASE pki_tenant_{uuid}`
3. Create PostgreSQL schemas: `ca`, `ra`, `validation`, `audit`
4. Create PostgreSQL roles: `ca_role`, `ra_role`, `val_role`, `audit_role`
5. Set grants per spec Section 2.2
6. Run migrations for all schemas
7. Insert tenant record in pki_platform.tenants

```elixir
defmodule PkiTenancy.Provisioner do
  def create_tenant(name, slug, opts \\ []) do
    # 1. Generate tenant UUID and database name
    # 2. Create database
    # 3. Create schemas and roles
    # 4. Run migrations
    # 5. Insert tenant record
  end

  def suspend_tenant(tenant_id)
  def activate_tenant(tenant_id)
  def delete_tenant(tenant_id)  # drops database
end
```

- [ ] **Step 1: Write failing tests** — create tenant, verify DB exists, verify schemas, verify roles
- [ ] **Step 2: Implement Provisioner**
- [ ] **Step 3: Run tests** (requires PostgreSQL running on port 5434)
- [ ] **Step 4: Commit**

---

### Task 5: Create Tenant Resolver

**Files:**
- Create: `src/pki_tenancy/lib/pki_tenancy/resolver.ex`
- Test: `src/pki_tenancy/test/pki_tenancy/resolver_test.exs`

Resolver extracts tenant from request context:
```elixir
defmodule PkiTenancy.Resolver do
  def resolve_from_subdomain(host)     # "tenant1.ca.example.com" → tenant
  def resolve_from_header(conn)        # X-Tenant-ID header
  def resolve_from_session(session)    # session[:tenant_id]
  def resolve_from_api_key(api_key)    # lookup tenant from API key
end
```

- [ ] **Step 1: Write failing tests**
- [ ] **Step 2: Implement Resolver**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

### Task 6: Create Platform Portal — project skeleton

**Files:**
- Create: `src/pki_platform_portal/` — full Phoenix project
- Key files: mix.exs, application.ex, router.ex, endpoint.ex, layouts.ex

This is a new Phoenix LiveView application. Use the same pattern as pki_ca_portal but simpler — fewer pages, same daisyUI styling.

- [ ] **Step 1: Generate Phoenix project structure** (manually, matching existing portal patterns)
- [ ] **Step 2: Configure for port 4006**
- [ ] **Step 3: Add pki_tenancy dep**
- [ ] **Step 4: Verify compilation**
- [ ] **Step 5: Commit**

---

### Task 7: Platform Portal — Login + Dashboard

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_html/login.html.heex`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/dashboard_live.ex`

Platform admin login (simple username/password from .env for now).
Dashboard shows: tenant count, total users across tenants, system health.

- [ ] **Step 1: Write login controller** — reads PLATFORM_ADMIN_USERNAME/PASSWORD from env
- [ ] **Step 2: Write dashboard LiveView** — lists tenants with status
- [ ] **Step 3: Write tests**
- [ ] **Step 4: Commit**

---

### Task 8: Platform Portal — Tenant Management (CRUD)

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenants_live.ex`

Tenants page: list, create, suspend, activate, delete.

Create flow:
1. Enter: org name, subdomain slug
2. System provisions database via Provisioner
3. Returns setup URL for tenant admin

- [ ] **Step 1: Write TenantsLive** — table with pagination, create form, status actions
- [ ] **Step 2: Wire to Provisioner** — create calls Provisioner.create_tenant
- [ ] **Step 3: Write tests**
- [ ] **Step 4: Commit**

---

### Task 9: Wire tenancy into existing services

**Files:**
- Modify: `src/pki_ca_engine/mix.exs` — add pki_tenancy dep
- Modify: `src/pki_ra_engine/mix.exs` — add pki_tenancy dep
- Modify: `src/pki_validation/mix.exs` — add pki_tenancy dep
- Modify: `src/pki_ca_portal/mix.exs` — add pki_tenancy dep
- Modify: `src/pki_ra_portal/mix.exs` — add pki_tenancy dep

Each service needs:
1. A Plug/middleware that resolves tenant from request
2. Sets the dynamic repo to the tenant's database
3. Sets the search_path to the service's schema

For this task, add the dep and create the middleware. Don't modify existing business logic — just add the tenant context layer that wraps requests.

- [ ] **Step 1: Add pki_tenancy dep to all services**
- [ ] **Step 2: Create tenant middleware Plug for each service**
- [ ] **Step 3: Run all tests** — existing tests must still pass
- [ ] **Step 4: Commit**

---

### Task 10: Update compose.yml + .env

**Files:**
- Modify: `compose.yml` — add pki-platform-portal service on port 4006
- Modify: `.env.example` — add PLATFORM_ADMIN_USERNAME, PLATFORM_ADMIN_PASSWORD
- Create: `src/pki_platform_portal/Containerfile`

- [ ] **Step 1: Add platform portal to compose.yml**
- [ ] **Step 2: Update .env.example**
- [ ] **Step 3: Create Containerfile**
- [ ] **Step 4: Build and test** — `podman-compose build pki-platform-portal`
- [ ] **Step 5: Commit and push**

---

## Plan Summary

| Task | What | Tests |
|------|------|-------|
| 1 | pki_tenancy mix project skeleton | Compiles |
| 2 | PlatformRepo + Tenant schema | ~10 tests |
| 3 | TenantRepo (dynamic DB routing) | ~6 tests |
| 4 | Database Provisioner | ~8 tests |
| 5 | Tenant Resolver | ~8 tests |
| 6 | Platform Portal skeleton | Compiles |
| 7 | Platform Portal login + dashboard | ~6 tests |
| 8 | Platform Portal tenant CRUD | ~8 tests |
| 9 | Wire tenancy into existing services | All existing pass |
| 10 | compose.yml + Containerfile | Builds |

**Total: ~50 new tests + all existing tests still passing**

Next plan (Plan 3: Credential Manager) will be written after this plan is implemented.
