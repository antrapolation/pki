# Phase C: Operations — Monitoring, Backup, Caddy

**Date:** 2026-04-19
**Goal:** Add observability, disaster recovery, and production-grade reverse proxy configuration. Three independent workstreams that make the per-tenant BEAM architecture operable.
**Duration:** ~2 weeks.
**Prerequisite:** Phase A + B complete on `feat/phase-a-per-tenant-beam` branch.

---

## 1. Monitoring — LiveDashboard + Health Endpoint

### LiveDashboard

Add `phoenix_live_dashboard` to the platform portal (`pki_platform_portal`). Accessible at `platform.straptrust.com/dashboard`.

**Custom "Tenant Health" page** that shows:
- All tenant nodes with status (running/stopped/crashed)
- Per-tenant: Mnesia table count, active key count, last backup time
- Replica node status (connected/disconnected)
- Data fetched via `:erpc.call(tenant_node, PkiTenant.Health, :check, [], 5000)` for each tenant

Uses distributed Erlang — the platform portal can reach all tenant nodes because they're in the same cluster.

LiveDashboard is auth-gated behind the platform admin session (existing auth). No public access.

### Health JSON Endpoint

**Platform health** at `platform.straptrust.com/health`:
```json
{
  "status": "healthy",
  "tenants": {
    "comp-5": {"status": "running", "mnesia": "ok", "active_keys": 2, "last_backup": "2026-04-19T10:00:00Z"},
    "comp-4": {"status": "running", "mnesia": "ok", "active_keys": 1, "last_backup": "2026-04-19T10:00:00Z"}
  },
  "replica": {"status": "connected", "node": "pki_replica@server2"}
}
```

**Tenant health** at `<slug>.ca.straptrust.com/health`:
```json
{
  "status": "healthy",
  "mnesia": "running",
  "tables": 16,
  "active_keys": 2,
  "last_backup": "2026-04-19T10:00:00Z",
  "uptime_seconds": 86400
}
```

Both endpoints unauthenticated (for uptime monitors like UptimeRobot, Healthchecks.io). No sensitive data exposed.

### Tenant Health module enhancement

`PkiTenant.Health.check/0` (already exists) needs to return richer data:
- Mnesia status + table count
- Active key count from `PkiCaEngine.KeyActivation`
- Last backup timestamp from `PkiTenant.MnesiaBackup`
- Uptime (process start time)

---

## 2. Per-Tenant Mnesia Backup to Object Storage

### Backup flow

Extend existing `PkiTenant.MnesiaBackup` GenServer:

1. **Local backup** — `mnesia:backup/1` to `/var/lib/pki/tenants/<slug>/backups/` (already implemented)
2. **Encrypt** — pipe through `age` encryption using the tenant's age public key
3. **Upload** — HTTP PUT to S3-compatible storage via `Req` library (already a dep)
4. **Record** — write `%BackupRecord{}` to Mnesia tracking backup history
5. **Prune local** — keep last 24 hourly backups (already implemented)

### Schedule

- **Hourly:** local backup (already running)
- **Daily:** off-host upload of latest local backup to S3 (new)
- Configurable via env vars: `BACKUP_S3_BUCKET`, `BACKUP_S3_ENDPOINT`, `BACKUP_S3_ACCESS_KEY`, `BACKUP_S3_SECRET_KEY`, `BACKUP_AGE_RECIPIENT`

### New Mnesia table

```elixir
:backup_records → %BackupRecord{
  id: binary,
  timestamp: DateTime.t(),
  type: String.t(),        # "local" | "remote"
  size_bytes: integer,
  location: String.t(),    # file path or S3 URL
  status: String.t(),      # "completed" | "failed"
  error: String.t() | nil,
  inserted_at: DateTime.t()
}
```

Added to `PkiMnesia.Schema.create_tables/0` as `disc_copies`. Added to `@sync_tables` for replication.

### S3 upload implementation

Use `Req` with S3v4 signature (simple module, no `ex_aws` dep needed):

```elixir
defmodule PkiTenant.S3Upload do
  def put_object(bucket, key, body, opts) do
    endpoint = opts[:endpoint] || "https://s3.amazonaws.com"
    access_key = opts[:access_key]
    secret_key = opts[:secret_key]
    # S3v4 signature + Req.put
  end
end
```

### Restore procedure

```bash
# List backups
aws s3 ls s3://pki-backups/tenant-comp5/

# Download
aws s3 cp s3://pki-backups/tenant-comp5/mnesia-2026-04-19.bak.age .

# Decrypt
age -d -i /etc/pki/age.key mnesia-2026-04-19.bak.age > mnesia.bak

# Restore (in tenant IEx)
:mnesia.restore('mnesia.bak', [{:default_op, :recreate_tables}])
```

Documented in `deploy/RESTORE.md`.

---

## 3. Dynamic Caddy Configuration

### URL structure

| Service | URL | Wildcard cert |
|---------|-----|---------------|
| Platform portal | `platform.straptrust.com` | `*.straptrust.com` |
| Tenant CA portal | `<slug>.ca.straptrust.com` | `*.ca.straptrust.com` |
| Tenant RA portal | `<slug>.ra.straptrust.com` | `*.ra.straptrust.com` |
| Tenant OCSP | `<slug>.ocsp.straptrust.com` | `*.ocsp.straptrust.com` |

3 wildcard certs for tenant services + 1 regular cert for platform. All via DNS-01 challenge with GoDaddy API.

### Caddy setup

Build Caddy with GoDaddy DNS plugin:
```bash
xcaddy build --with github.com/caddy-dns/godaddy
```

Base Caddyfile (TLS + admin API only):
```
{
  admin localhost:2019
}
```

TLS configuration injected via Caddy admin API JSON config, not Caddyfile. This allows dynamic route management.

### CaddyConfigurator changes

Update `PkiPlatformEngine.CaddyConfigurator.add_route/2` to register 3 hostnames per tenant:
- `<slug>.ca.straptrust.com` → `localhost:<port>`
- `<slug>.ra.straptrust.com` → `localhost:<port>`
- `<slug>.ocsp.straptrust.com` → `localhost:<port>`

All three point to the same tenant port — the tenant's HostRouter dispatches by hostname to the correct service (CA router, RA router, or OCSP endpoint).

`remove_route/1` removes all 3 routes (already uses named route IDs from Phase B fix: `route-<slug>`).

### HostRouter update

Update `PkiTenantWeb.HostRouter.extract_service/1` to handle OCSP:
```elixir
defp extract_service(host) do
  case host |> String.split(".") do
    [_slug, "ca" | _]   -> :ca
    [_slug, "ra" | _]   -> :ra
    [_slug, "ocsp" | _] -> :ocsp
    _                    -> :ca  # default for localhost/dev
  end
end
```

OCSP requests dispatch to `PkiValidation.OcspResponder` (HTTP POST handler, already exists).

### GoDaddy DNS credentials

Env vars on the Caddy host:
- `GODADDY_API_KEY`
- `GODADDY_API_SECRET`

Caddy's TLS automation config references these for DNS-01 challenges.

### Initial route setup on platform boot

`CaddyConfigurator` runs after `TenantLifecycle` boots all tenants. For each started tenant, registers routes. On subsequent tenant starts/stops, updates dynamically.

---

## 4. Changes to Existing Code

### New files

| File | Purpose |
|------|---------|
| `src/pki_platform_portal/lib/.../live/tenant_dashboard_live.ex` | LiveDashboard custom page for tenant health |
| `src/pki_platform_portal/lib/.../controllers/health_controller.ex` | Platform health JSON endpoint |
| `src/pki_tenant_web/lib/.../controllers/health_controller.ex` | Tenant health JSON endpoint |
| `src/pki_tenant/lib/pki_tenant/s3_upload.ex` | S3v4 signed upload via Req |
| `src/pki_mnesia/lib/pki_mnesia/structs/backup_record.ex` | BackupRecord struct |
| `deploy/Caddyfile.template` | Base Caddy config template |
| `deploy/RESTORE.md` | Backup restore runbook |

### Modified files

| File | Change |
|------|--------|
| `src/pki_tenant/lib/pki_tenant/health.ex` | Richer health data (active keys, last backup, uptime) |
| `src/pki_tenant/lib/pki_tenant/mnesia_backup.ex` | Add daily off-host upload, encrypt, record to Mnesia |
| `src/pki_mnesia/lib/pki_mnesia/schema.ex` | Add `backup_records` table, update sync_tables |
| `src/pki_mnesia/lib/pki_mnesia/structs/backup_record.ex` | New struct |
| `src/pki_platform_engine/lib/pki_platform_engine/caddy_configurator.ex` | 3 hostnames per tenant (ca, ra, ocsp), GoDaddy TLS config |
| `src/pki_tenant_web/lib/pki_tenant_web/host_router.ex` | Add `:ocsp` service dispatch |
| `src/pki_tenant_web/lib/pki_tenant_web/ca_router.ex` | Add `/health` route (unauthenticated) |
| `src/pki_tenant_web/lib/pki_tenant_web/ra_router.ex` | Add `/health` route (unauthenticated) |
| `src/pki_platform_portal/mix.exs` | Add `phoenix_live_dashboard` dep |
| `src/pki_platform_portal/lib/.../router.ex` | Add `/dashboard` route |

### Unchanged

- `pki_crypto` — no changes
- `pki_ca_engine`, `pki_ra_engine`, `pki_validation` — no changes
- `pki_replica` — no changes (benefits from backup_records replication automatically)

---

## 5. Testing Strategy

**Monitoring tests:**
- Health endpoint returns correct JSON structure
- Health endpoint is unauthenticated (no session required)
- `PkiTenant.Health.check/0` returns all expected fields
- LiveDashboard mounts (basic render test)

**Backup tests:**
- `S3Upload.put_object/4` with a mock HTTP server
- `MnesiaBackup` daily upload schedule triggers
- `BackupRecord` written to Mnesia after successful backup
- Backup failure recorded with error message

**Caddy tests:**
- `CaddyConfigurator.add_route/2` generates correct JSON for 3 hostnames
- `HostRouter.extract_service/1` returns `:ocsp` for `*.ocsp.*` hostnames
- Route removal cleans up all 3 hostnames

---

## 6. Success Criteria

- [ ] LiveDashboard accessible at `platform.straptrust.com/dashboard` (auth-gated)
- [ ] Custom tenant health page shows all tenant nodes with status, active keys, last backup
- [ ] Platform `/health` returns JSON with all tenant statuses
- [ ] Tenant `/health` returns JSON with Mnesia, key, backup status
- [ ] Hourly local Mnesia backups (existing) + daily encrypted upload to S3
- [ ] `BackupRecord` written to Mnesia after each backup (queryable for health endpoint)
- [ ] Restore procedure documented and tested
- [ ] Caddy routes 3 hostnames per tenant (ca, ra, ocsp) to the correct port
- [ ] Caddy auto-provisions wildcard TLS certs via GoDaddy DNS-01
- [ ] OCSP requests at `<slug>.ocsp.straptrust.com` reach the tenant's OCSP responder
- [ ] HostRouter dispatches `:ocsp` service correctly

## 7. Out of Scope

- Prometheus/Grafana — deferred until 50+ tenants
- Hot code upgrades — deferred, `peer` restart is fast enough
- Platform HA — deferred
- Custom tenant domains — deferred to BYOK milestone
- Alerting rules — use external uptime monitor against `/health` endpoint
