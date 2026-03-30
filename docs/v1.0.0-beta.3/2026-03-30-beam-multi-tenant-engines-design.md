# BEAM Multi-Tenant Engine Provisioning Design

**Date:** 2026-03-30
**Status:** Approved
**Version:** 1.0.0-beta.3

## Overview

Evolve from manually started per-tenant engine processes to a single BEAM node that dynamically provisions CA/RA engine processes for each active tenant. On tenant activation, the platform starts supervised engine processes connected to that tenant's database. On boot, all active tenants are restored.

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Portal-to-engine communication | Hybrid: direct Elixir calls internally, HTTP API for external consumers | Best performance for portals, HTTP stays for SSDID/API key consumers |
| Repo strategy | Connection pool per tenant (dynamic Ecto Repo) | Matches production (separate DB per tenant), warm pools, established Ecto pattern |
| Engine lifecycle | Start on boot (active tenants) + on activation (new tenants) | No cold-start latency after deploys, immediate availability |

## Architecture

### Process Tree

```
PkiPlatformEngine.Application
├── PlatformRepo (pki_platform_dev)
├── TenantSupervisor (DynamicSupervisor)
│   ├── TenantProcess (tenant-a)
│   │   ├── CA Repo → tenant_a DB, search_path: ca
│   │   ├── RA Repo → tenant_a DB, search_path: ra
│   │   ├── Audit Repo → tenant_a DB, search_path: ca
│   │   └── CA Engine GenServer
│   ├── TenantProcess (tenant-b)
│   │   ├── CA Repo → tenant_b DB, search_path: ca
│   │   ├── RA Repo → tenant_b DB, search_path: ra
│   │   ├── Audit Repo → tenant_b DB, search_path: ca
│   │   └── CA Engine GenServer
```

### Components

#### TenantSupervisor

- `DynamicSupervisor` started by `PkiPlatformEngine.Application`
- Children are `TenantProcess` supervisors, one per active tenant
- On application boot, reads all active tenants from `PlatformRepo` and starts a `TenantProcess` for each

#### TenantProcess

- Per-tenant `Supervisor` (`:one_for_all` strategy — if any child dies, restart all)
- Starts: CA Repo, RA Repo, Audit Repo, CA Engine GenServer
- Registered in `TenantRegistry` by tenant ID and slug
- Init receives tenant record (id, slug, database_name)

#### TenantRegistry

- ETS-based registry: `tenant_id → %{ca_repo: pid, ra_repo: pid, audit_repo: pid, engine: pid, tenant: tenant}`
- Also indexed by slug for portal lookups (user session carries slug)
- Functions: `lookup(tenant_id)`, `lookup_by_slug(slug)`, `register(tenant_id, pids)`, `unregister(tenant_id)`

#### Dynamic Repos

Each tenant gets three dynamic Ecto Repo instances:

```elixir
# CA Repo for tenant
Ecto.Repo.start_link(
  name: {:via, Registry, {TenantRepoRegistry, {tenant_id, :ca}}},
  database: tenant.database_name,
  after_connect: {Postgrex, :query!, ["SET search_path TO ca", []]},
  pool_size: 5
)
```

Engine modules accept a `repo` parameter (or resolve it from tenant context):

```elixir
# Before (single repo):
PkiCaEngine.Repo.all(CaInstance)

# After (tenant-aware):
repo = TenantRegistry.ca_repo(tenant_id)
repo.all(CaInstance)
```

### Communication Patterns

#### Internal (Portal → Engine)

Portals call engine modules directly. The portal resolves tenant from the session:

```elixir
# In CA Portal LiveView
tenant_id = socket.assigns.current_user.tenant_id
{:ok, instances} = PkiCaEngine.CaInstanceManagement.list_hierarchy(tenant_id)
```

Engine functions accept `tenant_id` as first parameter, resolve the dynamic Repo internally:

```elixir
def list_hierarchy(tenant_id) do
  repo = PkiPlatformEngine.TenantRegistry.ca_repo(tenant_id)
  # ... use repo instead of PkiCaEngine.Repo
end
```

#### External (HTTP API)

The existing HTTP API on ports 4001/4003 adds tenant context via header:

```
GET /api/v1/ca-instances
X-Tenant-ID: 019d3ee0-5002-746c-abf5-b5a974834810
Authorization: Bearer <secret>
```

The auth plug extracts `X-Tenant-ID` and puts it in `conn.assigns.tenant_id`. Engine controllers use it to resolve the dynamic Repo.

### Lifecycle

#### Boot

```elixir
# In PkiPlatformEngine.Application.start/2
def start(_type, _args) do
  children = [
    PlatformRepo,
    TenantRegistry,
    TenantSupervisor,
    {Task, &boot_active_tenants/0}  # async, after supervisor is ready
  ]
  Supervisor.start_link(children, strategy: :one_for_one)
end

defp boot_active_tenants do
  Provisioner.list_tenants()
  |> Enum.filter(&(&1.status == "active"))
  |> Enum.each(&TenantSupervisor.start_tenant/1)
end
```

#### Activate Tenant

```elixir
def activate_tenant(tenant_id) do
  with {:ok, tenant} <- get_tenant(tenant_id),
       {:ok, tenant} <- update_status(tenant, "active"),
       :ok <- TenantSupervisor.start_tenant(tenant),
       :ok <- wait_for_healthy(tenant_id, timeout: 10_000) do
    # Engines are running — create admins
    create_ca_admin(tenant)
    create_ra_admin(tenant)
    send_credentials_email(tenant)
    {:ok, tenant}
  end
end
```

#### Suspend Tenant

```elixir
def suspend_tenant(tenant_id) do
  TenantSupervisor.stop_tenant(tenant_id)
  update_status(tenant_id, "suspended")
end
```

### Module Changes

| Module | Change |
|---|---|
| `PkiPlatformEngine.Application` | Add TenantRegistry, TenantSupervisor to children. Boot active tenants on start. |
| `PkiPlatformEngine.TenantSupervisor` | **New** — DynamicSupervisor. Functions: `start_tenant/1`, `stop_tenant/1` |
| `PkiPlatformEngine.TenantProcess` | **New** — Per-tenant Supervisor. Starts dynamic Repos + Engine. |
| `PkiPlatformEngine.TenantRegistry` | **New** — ETS registry. Lookup by tenant_id or slug. |
| `PkiPlatformEngine.Provisioner` | Modify `activate_tenant` to start TenantProcess + create admins. Modify `suspend_tenant` to stop TenantProcess. |
| `PkiCaEngine.CaInstanceManagement` | Add `tenant_id` parameter to all public functions. Resolve dynamic Repo internally. |
| `PkiCaEngine.IssuerKeyManagement` | Same — add `tenant_id` parameter. |
| `PkiCaEngine.CertificateSigning` | Same — add `tenant_id` parameter. |
| `PkiCaEngine.KeystoreManagement` | Same — add `tenant_id` parameter. |
| `PkiCaEngine.KeyCeremonyManager` | Same — pass tenant_id through ceremony lifecycle. |
| `PkiCaEngine.UserManagement` | Same — add `tenant_id` parameter. |
| `PkiCaEngine.Engine` | Modify to be tenant-aware. Register per tenant_id. |
| `PkiRaEngine.RaInstanceManagement` | Add `tenant_id` parameter. |
| `PkiRaEngine.CsrValidation` | Add `tenant_id` parameter. |
| `PkiRaEngine.CertProfileConfig` | Add `tenant_id` parameter. |
| `PkiRaEngine.UserManagement` | Add `tenant_id` parameter. |
| `PkiRaEngine.ApiKeyManagement` | Add `tenant_id` parameter. |
| `PkiAuditTrail` | Add `tenant_id` parameter. Use dynamic Repo. |
| CA Portal LiveViews | Replace `CaEngineClient.Http` calls with direct Elixir calls via engine modules. Pass `tenant_id` from session. |
| RA Portal LiveViews | Same — replace `RaEngineClient.Http` calls with direct Elixir calls. |
| CA Portal `CaEngineClient` | Keep behaviour but add `:direct` implementation that calls engine modules. |
| RA Portal `RaEngineClient` | Same. |
| CA/RA Engine HTTP routers | Add `X-Tenant-ID` header extraction in auth plug. Pass `tenant_id` to controllers. |

### Portal Session Changes

The CA/RA portal auth flow needs to know which tenant the user belongs to:

1. User logs into CA portal with username + password
2. Auth plug sends credentials to CA engine HTTP API (or direct call)
3. CA engine authenticates against the tenant's CA Repo
4. Session stores `tenant_id` alongside `user_id` and `role`
5. All subsequent LiveView mounts read `tenant_id` from session
6. LiveViews pass `tenant_id` to engine module calls

### Migration Strategy

To avoid a big-bang rewrite, implement in phases:

1. **Phase 1: Infrastructure** — TenantSupervisor, TenantProcess, TenantRegistry, dynamic Repos
2. **Phase 2: Engine tenant-awareness** — Add `tenant_id` parameter to engine modules, use dynamic Repo lookup. Keep existing single-Repo as fallback for backward compat.
3. **Phase 3: Portal direct calls** — Add `:direct` CaEngineClient/RaEngineClient implementations that call engine modules. Switch portals to use them.
4. **Phase 4: Activation flow** — Wire up `activate_tenant` → start TenantProcess → create admins → send email
5. **Phase 5: Boot recovery** — On app start, restore all active tenants
6. **Phase 6: HTTP API tenant-awareness** — Add X-Tenant-ID header support to engine HTTP APIs

### Health Check

```elixir
def wait_for_healthy(tenant_id, opts \\ []) do
  timeout = Keyword.get(opts, :timeout, 10_000)

  # Poll every 500ms until tenant's Repos are connected
  deadline = System.monotonic_time(:millisecond) + timeout
  do_health_check(tenant_id, deadline)
end
```

### What Stays the Same

- Database-per-tenant architecture (each tenant has its own PostgreSQL database)
- Separate `ca`/`ra` schemas within each tenant database
- Tenant provisioning SQL (pg_dump based schema creation)
- CA/RA portal UI (LiveView pages)
- Engine business logic (hierarchy, ceremonies, CSR validation, etc.)

### What Changes

- No more manually starting engine processes per tenant
- No more separate ports per tenant (one node, one set of ports)
- Portals call engines directly (no HTTP round-trip for internal calls)
- Tenant context flows through session → LiveView → engine calls
- Activation is a one-click operation (start engines + create admins + email)

## Out of Scope

- Container orchestration (this replaces it with BEAM native multi-tenancy)
- Horizontal scaling across multiple nodes (future — BEAM distribution)
- Tenant resource limits (CPU/memory per tenant — future billing feature)
- Hot-swapping tenant database connections (restart TenantProcess instead)
