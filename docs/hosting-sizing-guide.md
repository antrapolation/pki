# PQC Certificate Authority System — Hosting & Sizing Guide

## Overview

This guide provides resource sizing recommendations for deploying the PKI CA system across different scales — from development environments to national-scale sovereign CA infrastructure.

All sizing assumes Elixir/OTP releases running on Linux (x86_64 or ARM64) with PostgreSQL 17 and Podman containers.

---

## Service Resource Profiles

### Per-Service Baseline (Idle)

| Service | CPU | RAM | Disk | Network | Notes |
|---------|-----|-----|------|---------|-------|
| PostgreSQL | 0.5 core | 512 MB | 10 GB | Low | Shared instance for dev; separate for prod |
| SSDID Registry | 0.25 core | 256 MB | 1 GB | Low | Mnesia disc_copies + Phoenix HTTP |
| CA Engine | 0.5 core | 512 MB | 1 GB | Low | GenServer state, no sustained load |
| CA Portal | 0.25 core | 256 MB | 100 MB | Low | Phoenix LiveView, no DB |
| RA Engine | 0.5 core | 512 MB | 1 GB | Medium | REST API, CSR processing |
| RA Portal | 0.25 core | 256 MB | 100 MB | Low | Phoenix LiveView, no DB |
| Validation (OCSP/CRL) | 0.5 core | 512 MB | 500 MB | High | Read-heavy, ETS cache |

### Peak Resource Usage by Operation

| Operation | CPU Spike | RAM Spike | Duration | Frequency |
|-----------|-----------|-----------|----------|-----------|
| Key ceremony (PQC) | 2-4 cores | +1 GB | 10-60s | Rare (yearly for root) |
| Key ceremony (RSA-4096) | 1-2 cores | +256 MB | 5-30s | Rare |
| Certificate signing (PQC) | 1-2 cores | +512 MB | 1-5s | Per cert request |
| Certificate signing (RSA/ECC) | 0.5 core | +128 MB | <1s | Per cert request |
| CSR validation | 0.25 core | +64 MB | <100ms | Per submission |
| OCSP response | 0.1 core | +16 MB | <10ms | Per query (cached) |
| CRL generation | 0.5 core | +256 MB | 1-10s | Periodic (hourly) |
| Audit log write | 0.1 core | +8 MB | <50ms | Per operation |

**Note:** PQC operations (KAZ-SIGN, ML-DSA) require the JRuby/BouncyCastle bridge which adds JVM overhead. Budget extra RAM for the Java process.

---

## Deployment Tiers

### Tier 1: Development / Testing

**Use case:** Developer workstation, CI pipeline, demo environment.

**Topology:** Single machine, all services in Podman Compose.

| Resource | Specification |
|----------|--------------|
| Machine | 1x laptop/VM |
| CPU | 4 cores |
| RAM | 8 GB |
| Disk | 50 GB SSD |
| OS | macOS (Podman Desktop) or Linux |
| Cost | $0 (local) or ~$40/mo (cloud VM) |

```
┌──────────────────────────────────┐
│  Single Machine (4 CPU, 8 GB)    │
│                                  │
│  ┌──────────┐  ┌──────────────┐  │
│  │ Postgres │  │ SSDID Reg.   │  │
│  │ 512 MB   │  │ 256 MB       │  │
│  └──────────┘  └──────────────┘  │
│  ┌──────────┐  ┌──────────────┐  │
│  │ CA Engine│  │ RA Engine    │  │
│  │ 512 MB   │  │ 512 MB       │  │
│  └──────────┘  └──────────────┘  │
│  ┌──────────┐  ┌──────────────┐  │
│  │ CA Portal│  │ RA Portal    │  │
│  │ 256 MB   │  │ 256 MB       │  │
│  └──────────┘  └──────────────┘  │
│  ┌──────────────────────────────┐│
│  │ Validation (OCSP/CRL)       ││
│  │ 512 MB                      ││
│  └──────────────────────────────┘│
└──────────────────────────────────┘

Total: ~3 GB RAM allocated to services
Remaining: ~5 GB for OS, builds, JVM
```

**Cloud equivalent:**

| Provider | Instance | vCPU | RAM | Disk | Monthly Cost |
|----------|----------|------|-----|------|-------------|
| AWS | t3.large | 2 | 8 GB | 50 GB gp3 | ~$60 |
| GCP | e2-standard-2 | 2 | 8 GB | 50 GB SSD | ~$50 |
| Azure | B2s | 2 | 4 GB | 50 GB SSD | ~$35 |
| DigitalOcean | s-2vcpu-4gb | 2 | 4 GB | 80 GB | ~$24 |
| Hetzner | CPX21 | 3 | 4 GB | 80 GB | ~€8 |

---

### Tier 2: Small Organization / Pilot

**Use case:** Single enterprise or agency, <100 certs/day, <10 concurrent users.

**Topology:** 2 servers — CA isolated from everything else.

| Server | Role | CPU | RAM | Disk | Monthly Cost |
|--------|------|-----|-----|------|-------------|
| CA Server | CA Engine + CA Portal | 2 cores | 4 GB | 50 GB SSD | ~$30-60 |
| App Server | RA Engine + RA Portal + Validation + SSDID + Postgres | 4 cores | 8 GB | 100 GB SSD | ~$50-80 |
| **Total** | | **6 cores** | **12 GB** | **150 GB** | **~$80-140/mo** |

```
┌─────────────────────┐     ┌──────────────────────────┐
│  CA Server           │     │  App Server               │
│  (2 CPU, 4 GB)       │     │  (4 CPU, 8 GB)            │
│                      │     │                            │
│  CA Engine  (1 GB)   │◄───►│  RA Engine   (1 GB)       │
│  CA Portal  (512 MB) │     │  RA Portal   (512 MB)     │
│                      │     │  Validation  (1 GB)        │
│                      │     │  SSDID Reg.  (512 MB)      │
│                      │     │  Postgres    (2 GB)         │
└─────────────────────┘     └──────────────────────────┘
           ▲                            ▲
           │         Internal network   │
           └────────────────────────────┘
```

**Capacity estimates:**

| Metric | Capacity |
|--------|----------|
| Certificates issued per day | ~100-500 |
| Concurrent portal users | ~10 |
| OCSP queries per second | ~50 |
| CRL size | <10,000 entries |
| Database size (1 year) | ~5 GB |
| Audit events (1 year) | ~500,000 |

---

### Tier 3: Medium Enterprise / Government Agency

**Use case:** Department-level CA, <10,000 certs/day, <50 concurrent users, HSM required.

**Topology:** 3+ servers with database replication.

| Server | Role | CPU | RAM | Disk | Qty | Monthly Cost |
|--------|------|-----|-----|------|-----|-------------|
| CA Server | CA Engine (with HSM) | 4 cores | 8 GB | 100 GB NVMe | 2 (HA) | ~$200 |
| App Server | RA Engine + Portals + SSDID | 4 cores | 8 GB | 100 GB SSD | 2 (HA) | ~$160 |
| Validation | OCSP + CRL | 2 cores | 4 GB | 50 GB SSD | 2-4 | ~$120-240 |
| DB Primary | PostgreSQL | 4 cores | 16 GB | 500 GB NVMe | 1 | ~$150 |
| DB Replica | PostgreSQL (read) | 2 cores | 8 GB | 500 GB NVMe | 1-2 | ~$100-200 |
| **Total** | | **24-32 cores** | **60-80 GB** | **1.5-2 TB** | **8-12** | **~$730-950/mo** |

```
                    Load Balancer (Nginx/HAProxy)
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌─────────┐ ┌─────────┐ ┌─────────────┐
         │CA Portal│ │RA Portal│ │  RA Engine   │
         │ (HA x2) │ │ (HA x2) │ │  (HA x2)    │
         └────┬────┘ └────┬────┘ └──────┬───────┘
              │           │             │
              ▼           ▼             ▼
         ┌──────────────────────────────────┐
         │         CA Engine (HA x2)         │
         │         HSM Connected             │
         └───────────────┬──────────────────┘
                         │
              ┌──────────┼──────────┐
              ▼                     ▼
         ┌──────────┐       ┌───────────────┐
         │ Postgres  │──────►│ Postgres      │
         │ Primary   │       │ Replica (1-2) │
         └──────────┘       └───────┬───────┘
                                    │
                          ┌─────────┼─────────┐
                          ▼         ▼         ▼
                     ┌─────────┐┌────────┐┌─────────┐
                     │OCSP (1) ││OCSP (2)││OCSP (3) │
                     └─────────┘└────────┘└─────────┘
```

**Capacity estimates:**

| Metric | Capacity |
|--------|----------|
| Certificates issued per day | ~1,000-10,000 |
| Concurrent portal users | ~50 |
| OCSP queries per second | ~500-1,000 |
| CRL size | ~100,000 entries |
| Database size (1 year) | ~50 GB |
| Audit events (1 year) | ~5,000,000 |

**HSM requirements:**

| HSM Type | Use Case | Estimated Cost |
|----------|----------|---------------|
| SoftHSM 2 | Development/testing | Free (software) |
| Thales Luna Network HSM | Production, FIPS 140-3 L3 | ~$30,000-50,000 (one-time) |
| AWS CloudHSM | Cloud deployment | ~$1.50/hr (~$1,100/mo) |
| Azure Dedicated HSM | Cloud deployment | ~$4,600/mo |

---

### Tier 4: National / Sovereign CA (SaaS Multi-Tenant)

**Use case:** National PKI infrastructure, multiple CA tenants, >100,000 certs/day, >500 concurrent users.

**Topology:** Full isolation with dedicated hardware per security zone.

| Zone | Servers | Per Server | Total |
|------|---------|------------|-------|
| **CA Zone** | 2-4 per tenant (HA + standby) | 8 CPU, 16 GB, 200 GB NVMe | Scales with tenants |
| **Portal Zone** | 4-8 (load balanced) | 4 CPU, 8 GB, 50 GB SSD | ~$320-640/mo |
| **RA Zone** | 4-8 (load balanced) | 4 CPU, 8 GB, 100 GB SSD | ~$320-640/mo |
| **DMZ (Validation)** | 8-16 (OCSP/CRL pool) | 4 CPU, 8 GB, 50 GB SSD | ~$640-1,280/mo |
| **DB Zone** | 2-4 per tier (primary + replicas) | 8 CPU, 32 GB, 1 TB NVMe | ~$800-1,600/mo |
| **Audit Zone** | 2 (HA) | 4 CPU, 16 GB, 2 TB SSD | ~$400/mo |
| **SSDID Zone** | 3-5 (Mnesia cluster) | 4 CPU, 8 GB, 100 GB SSD | ~$240-400/mo |
| **HSM Cluster** | 2-4 (HA) | Network HSM | ~$100,000-200,000 (one-time) |

**Per-tenant CA node sizing:**

| Tenant Size | CA Nodes | CPU per Node | RAM per Node |
|-------------|----------|-------------|-------------|
| Small (<1K certs/day) | 2 (primary + standby) | 2 cores | 4 GB |
| Medium (<10K certs/day) | 2 | 4 cores | 8 GB |
| Large (<100K certs/day) | 2-4 | 8 cores | 16 GB |

**Total infrastructure estimate (10 tenants, medium load):**

| Component | Quantity | Specification | Monthly Cost |
|-----------|----------|---------------|-------------|
| CA nodes | 20 (2 per tenant) | 4 CPU, 8 GB | ~$1,600 |
| Portal nodes | 8 | 4 CPU, 8 GB | ~$640 |
| RA nodes | 8 | 4 CPU, 8 GB | ~$640 |
| Validation nodes | 12 | 4 CPU, 8 GB | ~$960 |
| DB nodes | 6 | 8 CPU, 32 GB | ~$1,200 |
| Audit nodes | 2 | 4 CPU, 16 GB | ~$400 |
| SSDID nodes | 3 | 4 CPU, 8 GB | ~$240 |
| Load balancers | 2 | 2 CPU, 4 GB | ~$80 |
| Monitoring | 1 | 4 CPU, 16 GB | ~$150 |
| **Total** | **62 servers** | **~248 CPU, ~600 GB RAM** | **~$5,910/mo** |
| HSM | 2-4 | Network HSM | ~$150,000 one-time |

**Capacity estimates at this scale:**

| Metric | Capacity |
|--------|----------|
| Total tenants | 10-50 |
| Certificates issued per day (total) | ~100,000-1,000,000 |
| Concurrent portal users | ~500+ |
| OCSP queries per second | ~10,000-50,000 |
| CRL size (per tenant) | ~1,000,000 entries |
| Database size (1 year, all tenants) | ~500 GB - 2 TB |
| Audit events (1 year) | ~50,000,000+ |

---

## Database Sizing

### Storage Growth Estimates

| Table | Avg Row Size | Growth Rate | 1 Year (1K certs/day) | 1 Year (100K certs/day) |
|-------|-------------|-------------|----------------------|------------------------|
| issued_certificates | ~2 KB | Per cert issued | ~730 MB | ~73 GB |
| csr_requests | ~3 KB | Per CSR submitted | ~1.1 GB | ~110 GB |
| audit_events | ~500 B | Per operation (~10x certs) | ~3.7 GB | ~370 GB |
| cert_profiles | ~2 KB | Rarely changes | <1 MB | <10 MB |
| ca_users / ra_users | ~200 B | Rarely changes | <1 MB | <1 MB |
| threshold_shares | ~1 KB | Per ceremony | <10 MB | <100 MB |
| key_ceremonies | ~500 B | Per ceremony | <1 MB | <10 MB |

### PostgreSQL Configuration

#### Small (Tier 1-2)

```ini
# postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 16MB
maintenance_work_mem = 128MB
max_connections = 50
```

#### Medium (Tier 3)

```ini
shared_buffers = 4GB
effective_cache_size = 12GB
work_mem = 64MB
maintenance_work_mem = 512MB
max_connections = 200
wal_level = replica
max_wal_senders = 5
```

#### Large (Tier 4)

```ini
shared_buffers = 8GB
effective_cache_size = 24GB
work_mem = 128MB
maintenance_work_mem = 1GB
max_connections = 500
wal_level = replica
max_wal_senders = 10
synchronous_commit = on
```

---

## Network Bandwidth

| Traffic Type | Per Request | Requests/sec (Tier 3) | Bandwidth |
|-------------|-------------|----------------------|-----------|
| OCSP query + response | ~1 KB | 1,000 | ~8 Mbps |
| CRL download | 10 KB - 10 MB | 10 | ~1-100 Mbps |
| CSR submission | ~5 KB | 10 | <1 Mbps |
| Portal WebSocket | ~200 B/msg | 50 users | <1 Mbps |
| Inter-node Erlang RPC | ~1 KB | 100 | <1 Mbps |
| DB queries | ~2 KB | 500 | ~8 Mbps |
| **Total estimated** | | | **~20-120 Mbps** |

**Recommendation:** 1 Gbps network minimum for Tier 3+. 10 Gbps for Tier 4 (especially validation DMZ).

---

## Scaling Playbook

### When to scale OCSP/Validation

| Signal | Threshold | Action |
|--------|-----------|--------|
| OCSP p99 latency | >100ms | Add validation node |
| OCSP cache hit rate | <80% | Increase ETS cache TTL or RAM |
| CPU utilization | >70% sustained | Add validation node |

### When to scale RA Engine

| Signal | Threshold | Action |
|--------|-----------|--------|
| CSR queue depth | >1,000 pending | Add RA engine node |
| API response time p99 | >500ms | Add RA engine node |
| DB connection pool exhausted | Pool wait >100ms | Increase pool_size or add node |

### When to scale CA Engine

| Signal | Threshold | Action |
|--------|-----------|--------|
| Signing queue latency | >2s | Verify key activation; check HSM throughput |
| Ceremony timeout | Frequent failures | Increase ceremony window; check network to HSM |

CA engine scaling is primarily vertical (faster HSM, more RAM) rather than horizontal, since each CA instance is a single process with threshold-activated keys.

### When to scale Database

| Signal | Threshold | Action |
|--------|-----------|--------|
| Query latency p99 | >50ms | Add read replica for validation queries |
| Disk usage | >70% | Expand storage; archive old audit events |
| Connection count | >80% of max_connections | Increase limit or add PgBouncer |
| Replication lag | >1s | Upgrade replica hardware |

---

## Cost Summary by Tier

| Tier | Use Case | Servers | Monthly Cost | Annual Cost |
|------|----------|---------|-------------|-------------|
| **1** | Dev/Testing | 1 | $0-60 | $0-720 |
| **2** | Small Org | 2 | $80-140 | $960-1,680 |
| **3** | Enterprise/Govt | 8-12 | $730-950 | $8,760-11,400 |
| **4** | National CA (10 tenants) | ~62 | ~$5,910 | ~$70,920 |
| **4** | National CA (50 tenants) | ~200 | ~$20,000 | ~$240,000 |

HSM costs (one-time, add to annual):

| Type | Cost |
|------|------|
| SoftHSM (dev) | Free |
| Cloud HSM (AWS/Azure) | $13,000-55,000/yr |
| Network HSM (Thales Luna) | $30,000-200,000 one-time |
