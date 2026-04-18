# Phase B: Multi-Host Mnesia Replication — Design Spec

**Date:** 2026-04-18
**Goal:** Add a second server as a warm standby with Mnesia replication for all tenant data. Automatic failure detection, manual promotion. Zero data loss for critical tables.
**Duration:** ~2 weeks.
**Prerequisite:** Phase A complete on `feat/phase-a-per-tenant-beam` branch.

---

## 1. Architecture Overview

Two servers: primary runs platform + all tenants, replica runs passive tenant copies.

**Primary (server 1):** Platform BEAM + tenant BEAM nodes (unchanged from Phase A). Serves all HTTP traffic.

**Replica (server 2):** Lightweight `pki_replica` app. No platform, no PostgreSQL. Joins the Erlang cluster via libcluster. For each tenant on the primary, spawns a replica BEAM node that receives Mnesia replication writes. No web endpoints, no signing, no OCSP — purely a data mirror.

**On failover (manual):** Operator runs a promotion command on server 2. Each replica tenant converts its `ram_copies` to `disc_copies`, starts the full engine + web supervision tree, allocates a port, and begins serving traffic. Operator updates DNS to point to server 2.

**Designed for N servers:** The abstraction (libcluster topology, replica supervisor, promotion manager) scales to 3+ servers. Phase B implements for 2; the extension point is the static node list in config and the placement strategy in TenantReplicaSupervisor.

---

## 2. Cluster Formation

**libcluster** connects platform (server 1) and replica supervisor (server 2) using `Cluster.Strategy.Epmd` with a static host list.

```elixir
config :libcluster,
  topologies: [
    pki_cluster: [
      strategy: Cluster.Strategy.Epmd,
      config: [hosts: [:"pki_platform@server1", :"pki_replica@server2"]]
    ]
  ]
```

**Tenant nodes** are connected by their supervisors (platform's TenantLifecycle and replica's TenantReplicaSupervisor) via `Node.connect` after spawn. No libcluster needed for tenant-to-tenant connections.

**Node naming:**
- Platform: `pki_platform@<hostname>`
- Replica supervisor: `pki_replica@<hostname>`
- Tenant primary: `tenant_<slug>@<hostname>`
- Tenant replica: `tenant_<slug>_replica@<hostname>`

**Cookie:** shared across all cluster nodes (same as Phase A).

**Firewall:** EPMD (4369) + distributed Erlang port range (9100-9200) open bidirectionally between server 1 and server 2. Tenant HTTP ports (5001-5999) open only on the server currently serving traffic.

---

## 3. Mnesia Replication

### Table strategy

| Table | Primary type | Replica type | Replication | Rationale |
|-------|-------------|-------------|-------------|-----------|
| `issuer_keys` | `disc_copies` | `ram_copies` | Synchronous | Key material — zero loss |
| `threshold_shares` | `disc_copies` | `ram_copies` | Synchronous | Share data — zero loss |
| `key_ceremonies` | `disc_copies` | `ram_copies` | Synchronous | Ceremony state — zero loss |
| `ceremony_participants` | `disc_copies` | `ram_copies` | Synchronous | Identity verification — zero loss |
| `ceremony_transcripts` | `disc_copies` | `ram_copies` | Synchronous | Audit evidence — zero loss |
| `ca_instances` | `disc_copies` | `ram_copies` | Synchronous | CA hierarchy — zero loss |
| `portal_users` | `disc_copies` | `ram_copies` | Synchronous | Auth data — zero loss |
| `cert_profiles` | `disc_copies` | `ram_copies` | Synchronous | Config — zero loss |
| `ra_instances` | `disc_copies` | `ram_copies` | Synchronous | Config — zero loss |
| `ra_ca_connections` | `disc_copies` | `ram_copies` | Synchronous | Config — zero loss |
| `api_keys` | `disc_copies` | `ram_copies` | Synchronous | Auth — zero loss |
| `dcv_challenges` | `disc_copies` | `ram_copies` | Synchronous | Validation state — small |
| `schema_versions` | `disc_copies` | `ram_copies` | Synchronous | Schema tracking — zero loss |
| `issued_certificates` | `disc_only_copies` | `disc_only_copies` | Asynchronous | Large, re-derivable |
| `csr_requests` | `disc_only_copies` | `disc_only_copies` | Asynchronous | Large, re-submittable |
| `certificate_status` | `disc_only_copies` | `disc_only_copies` | Asynchronous | Large, re-derivable |

### How sync/async works

**Synchronous (`disc_copies` primary + `ram_copies` replica):** Mnesia replicates within the same transaction. The transaction does not commit until both nodes acknowledge. Write latency increases by ~1-5ms (LAN round-trip).

**Asynchronous (`disc_only_copies` on both):** DETS writes are local. Mnesia sends change notifications to the replica which applies them eventually. Data loss window on failover: up to a few seconds.

### Replica join sequence

1. Replica tenant node starts with empty Mnesia (no schema)
2. Sets Mnesia directory to `/var/lib/pki/replicas/<slug>/mnesia`
3. Calls `:mnesia.start()` (no schema creation)
4. Calls `:mnesia.change_config(:extra_db_nodes, [primary_tenant_node])`
5. For each sync table: `:mnesia.add_table_copy(table, node(), :ram_copies)`
6. For each async table: `:mnesia.add_table_copy(table, node(), :disc_only_copies)`
7. `:mnesia.wait_for_tables(all_tables, 30_000)`
8. Reports `:replica_ready` to TenantReplicaSupervisor

### Data loss on failover

- Sync tables: zero loss
- Async tables: up to a few seconds of CSR submissions, certificate issuances, revocations. Recoverable — CSR can be resubmitted, certificate re-signed from the intact issuer key.

---

## 4. Health Monitoring + Failover

### Monitoring (runs on replica supervisor, server 2)

**Heartbeat:** `PkiReplica.ClusterMonitor` calls `:erpc.call(platform_node, :erlang, :node, [], 3000)` every 5 seconds. Three consecutive failures = primary declared unreachable.

**Per-tenant health:** Every 30 seconds, for each replicated tenant, calls `:erpc.call(tenant_primary_node, PkiTenant.Health, :check, [], 5000)`. Individual tenant failures do not trigger cluster failover — just log warnings.

### Alert (automatic)

When primary is declared unreachable, `PkiReplica.FailoverManager`:
1. Logs `[CRITICAL] Primary server unreachable — manual promotion required`
2. Writes to `/var/log/pki/failover-alert.log`
3. Calls a configurable webhook URL (PagerDuty/Slack/email integration)
4. Sets internal state to `:primary_down`
5. Does NOT auto-promote

### Promotion (manual)

Operator runs on server 2:
```bash
/opt/pki/bin/pki_replica eval "PkiReplica.FailoverManager.promote_all()"
```

**Per-tenant promotion steps:**
1. Final check that primary is truly unreachable
2. Convert `ram_copies` tables to `disc_copies` via `:mnesia.change_table_copy_type/3`
3. Start full tenant supervision tree (CA engine, RA engine, Validation, Phoenix endpoint)
4. Allocate HTTP port from local pool
5. Update local Caddy config for tenant subdomain routing
6. Log `[FAILOVER] Tenant <slug> promoted to primary on server 2`

**What promotion does NOT do:**
- Does not touch server 1 (may be unreachable)
- Does not update DNS (operator handles this separately)
- Does not start the platform node (platform HA deferred to Phase C)

### Recovery (server 1 comes back)

Manual process — no automatic failback (prevents flapping):
1. Operator decides role assignment: server 1 becomes new replica, or server 2 hands back
2. Demotion: `PkiReplica.FailoverManager.demote_to_replica()` on the server becoming replica
3. Demoted server re-joins Mnesia cluster as `ram_copies` replica
4. Operator updates DNS if needed

---

## 5. Replica Supervisor (New App: `pki_replica`)

### Supervision tree

```
PkiReplica.Application
├── PkiReplica.ClusterMonitor          # libcluster + heartbeat
├── PkiReplica.FailoverManager         # alert + manual promotion
├── PkiReplica.TenantReplicaSupervisor # manages replica tenant nodes
└── PkiReplica.PortAllocator           # local port pool for post-promotion
```

### TenantReplicaSupervisor

- On boot: connects to platform, calls `TenantLifecycle.list_tenants()`, spawns a replica for each running tenant
- Receives push notifications from platform when tenants start/stop (`GenServer.cast`)
- Backup: polls primary every 30 seconds for tenant list (handles missed notifications)
- Spawns replica tenant nodes via `:peer` with env `REPLICA_MODE=true`

### Replica tenant boot

1. `:peer.start_link` with env: `MNESIA_DIR=/var/lib/pki/replicas/<slug>/mnesia`, `PRIMARY_TENANT_NODE=tenant_<slug>@server1`, `REPLICA_MODE=true`
2. `PkiTenant.MnesiaBootstrap` detects `REPLICA_MODE=true`
3. Starts Mnesia without creating schema
4. Joins primary's Mnesia cluster via `:mnesia.change_config(:extra_db_nodes, ...)`
5. Adds table copies
6. Waits for tables
7. Sits idle receiving replication writes

### New release

```elixir
pki_replica: [
  applications: [
    pki_replica: :permanent,
    pki_mnesia: :permanent,
    pki_ca_engine: :load,      # loaded but not started (available for promotion)
    pki_ra_engine: :load,
    pki_validation: :load,
    pki_tenant: :load,
    pki_tenant_web: :load
  ]
]
```

Post-promotion, the loaded applications are started by `FailoverManager.promote_tenant/1`.

---

## 6. Changes to Existing Code

### PkiTenant.MnesiaBootstrap — add replica mode

```elixir
def init(opts) do
  if System.get_env("REPLICA_MODE") == "true" do
    join_existing_cluster(opts)
  else
    create_fresh_mnesia(opts)  # current behavior
  end
end

defp join_existing_cluster(opts) do
  slug = Keyword.get(opts, :slug, "dev")
  mnesia_dir = System.get_env("MNESIA_DIR") || "/var/lib/pki/replicas/#{slug}/mnesia"
  primary_node = System.get_env("PRIMARY_TENANT_NODE") |> String.to_atom()
  
  File.mkdir_p!(mnesia_dir)
  Application.put_env(:mnesia, :dir, String.to_charlist(mnesia_dir))
  
  :mnesia.start()
  PkiMnesia.Schema.add_replica_copies(primary_node)
  
  {:ok, %{dir: mnesia_dir, mode: :replica}}
end
```

### PkiMnesia.Schema — add replication functions

```elixir
@sync_tables [
  :ca_instances, :issuer_keys, :threshold_shares, :key_ceremonies,
  :ceremony_participants, :ceremony_transcripts, :portal_users,
  :cert_profiles, :ra_instances, :ra_ca_connections, :api_keys,
  :dcv_challenges, :schema_versions
]

@async_tables [:issued_certificates, :csr_requests, :certificate_status]

def add_replica_copies(primary_node) do
  :mnesia.change_config(:extra_db_nodes, [primary_node])
  
  for table <- @sync_tables do
    :mnesia.add_table_copy(table, node(), :ram_copies)
  end
  
  for table <- @async_tables do
    :mnesia.add_table_copy(table, node(), :disc_only_copies)
  end
  
  all_tables = @sync_tables ++ @async_tables
  :mnesia.wait_for_tables(all_tables, 30_000)
end

def promote_to_primary do
  for table <- @sync_tables do
    :mnesia.change_table_copy_type(table, node(), :disc_copies)
  end
  :ok
end

def demote_to_replica(primary_node) do
  :mnesia.change_config(:extra_db_nodes, [primary_node])
  for table <- @sync_tables do
    :mnesia.change_table_copy_type(table, node(), :ram_copies)
  end
  :ok
end
```

### PkiPlatformEngine.TenantLifecycle — notify replica on tenant changes

After tenant spawn success:
```elixir
GenServer.cast({PkiReplica.TenantReplicaSupervisor, replica_node()},
  {:tenant_started, %{tenant_id: id, slug: slug, node: node}})
```

After tenant stop:
```elixir
GenServer.cast({PkiReplica.TenantReplicaSupervisor, replica_node()},
  {:tenant_stopped, %{tenant_id: id}})
```

If replica is unreachable, `cast` silently drops. Replica's 30-second poll is the backup mechanism.

### No changes needed

- `pki_crypto` — unchanged
- `pki_ca_engine` — unchanged (Mnesia replication is transparent)
- `pki_ra_engine` — unchanged
- `pki_validation` — unchanged
- `pki_tenant_web` — unchanged
- `PkiMnesia.Repo` — unchanged (reads/writes go to local Mnesia; replication is handled by Mnesia internally)

---

## 7. Configuration

### Server 1 (primary) — additions to existing config

```elixir
# config/runtime.exs additions
config :libcluster,
  topologies: [
    pki_cluster: [
      strategy: Cluster.Strategy.Epmd,
      config: [
        hosts: [
          :"pki_platform@#{System.get_env("PRIMARY_HOSTNAME", "server1")}",
          :"pki_replica@#{System.get_env("REPLICA_HOSTNAME", "server2")}"
        ]
      ]
    ]
  ]
```

### Server 2 (replica) — new config

```elixir
# Replica-specific runtime config
config :pki_replica,
  primary_platform_node: :"pki_platform@#{System.get_env("PRIMARY_HOSTNAME", "server1")}",
  heartbeat_interval_ms: 5_000,
  heartbeat_failure_threshold: 3,
  tenant_poll_interval_ms: 30_000,
  webhook_url: System.get_env("FAILOVER_WEBHOOK_URL"),
  alert_log_path: "/var/log/pki/failover-alert.log"

config :libcluster,
  topologies: [
    pki_cluster: [
      strategy: Cluster.Strategy.Epmd,
      config: [
        hosts: [
          :"pki_platform@#{System.get_env("PRIMARY_HOSTNAME", "server1")}",
          :"pki_replica@#{System.get_env("REPLICA_HOSTNAME", "server2")}"
        ]
      ]
    ]
  ]
```

---

## 8. Testing Strategy

**Unit tests (no network):**
- `PkiMnesia.Schema.add_replica_copies/1` — mock the primary node, verify table copy calls
- `PkiMnesia.Schema.promote_to_primary/0` — verify table type changes
- `PkiReplica.ClusterMonitor` — heartbeat state machine (connected → failure → unreachable)
- `PkiReplica.FailoverManager` — state transitions (normal → primary_down → promoting → promoted)

**Integration tests (two-node, same host):**
- Start a primary tenant node + replica tenant node on localhost using `:peer`
- Write to primary's Mnesia, verify it appears on replica (sync table)
- Kill primary, verify replica has all data
- Promote replica, verify it can start the full supervision tree
- Verify signing works on promoted replica

**Manual acceptance test:**
- Two VPS servers provisioned
- Platform on server 1 with 2 tenants
- Replica on server 2 with 2 tenant replicas
- Kill server 1 process
- Verify alert fires within 15 seconds
- Run `promote_all()` on server 2
- Verify both tenants serve traffic on server 2
- Bring server 1 back as replica

---

## 9. Success Criteria

- [ ] libcluster connects platform and replica supervisor across two hosts
- [ ] Each tenant on primary has a corresponding replica receiving Mnesia writes
- [ ] Sync table writes (issuer_keys, threshold_shares, etc.) are zero-loss on failover
- [ ] Async table writes (issued_certificates, csr_requests) are eventually consistent
- [ ] ClusterMonitor detects primary unreachable within 15 seconds (3 × 5s heartbeats)
- [ ] FailoverManager fires webhook alert on primary unreachable
- [ ] Manual `promote_all()` converts replicas to primaries and starts tenant web+engines
- [ ] Promoted tenant can sign certificates and respond to OCSP
- [ ] `demote_to_replica()` converts a promoted server back to replica mode
- [ ] New tenant created on primary automatically gets a replica on server 2
- [ ] Tenant stopped on primary automatically removes its replica on server 2
- [ ] Write latency on sync tables increases by <5ms (LAN)

## 10. Out of Scope (deferred)

- Platform node HA (Phase C)
- Automatic promotion / split-brain prevention
- Per-tenant placement strategy across 3+ servers
- Cross-datacenter replication (requires TLS distribution)
- Per-tenant cookies for Erlang distribution
- Automatic DNS failover
