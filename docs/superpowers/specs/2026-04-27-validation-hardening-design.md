# Validation Service Hardening — Design Spec

**Date:** 2026-04-27
**Scope:** `pki_validation`, `pki_platform_engine`, `pki_tenant_web` docs, root docs

---

## Goal

Three production-readiness fixes for the OCSP/CRL validation service, plus removal of orphaned PostgreSQL validation schema artefacts and a documentation pass to reflect the one-BEAM-node-per-tenant architecture.

CDP/OCSP URL embedding in issued certificates is **out of scope** — that is a separate initiative.

---

## Architecture Context

The system runs one `pki_platform` BEAM VM for the platform tier (tenant registry, platform users, platform audit trail → PostgreSQL) and one `pki_tenant` BEAM VM per tenant. Each tenant BEAM runs:

- CA engine (in-process, no HTTP API)
- RA engine (in-process, no HTTP API)
- `pki_validation` — OCSP responder + CRL publisher (in-process)
- `pki_tenant_web` — CA + RA portal UI

All CA/RA/Validation state lives in the tenant's local **Mnesia**. PostgreSQL is platform-only.

The old schema-mode design (one shared BEAM, per-tenant PostgreSQL schemas `t_<hex>_{ca,ra,audit,validation}`) is deprecated. The `t_<hex>_validation` tables are orphaned; nothing reads or writes them.

---

## Fix 1 — RFC 6960 Nonce on Error Responses

### Problem

`ocsp/der_responder.ex` error paths (`:tryLater`, `:unauthorized`, `:internalError`) call `ResponseBuilder.build/3` without the client's nonce. RFC 6960 §4.4.1 requires the nonce to be echoed in all responses when present. Strict validators treat a missing nonce as a security failure.

### Fix

In `DerResponder.respond/2`, extract `nonce` from the parsed request before the signing-key resolution branch. Pass `nonce: nonce` to every `ResponseBuilder.build/4` call — both success and all error paths.

**Files touched:**
- `src/pki_validation/lib/pki_validation/ocsp/der_responder.ex` — pass nonce on all build calls
- `src/pki_validation/test/pki_validation/ocsp/der_responder_test.exs` — add nonce-on-error test case

### Test

Send an OCSP request with a nonce extension. Simulate a `:try_later` signing key state (mock `KeyActivation.lease_status/2` returning `:inactive`). Assert the response DER contains the nonce extension unchanged.

---

## Fix 2 — Per-Issuer CRL Scoping

### Problem

`CrlPublisher.do_generate_crl/0` queries all revoked `CertificateStatus` records with no `issuer_key_id` filter:

```elixir
Repo.where(CertificateStatus, fn cs -> cs.status == "revoked" end)
```

In a multi-issuer tenant (multiple CA instances), this produces one combined CRL mixing revocations from different issuers — invalid per RFC 5280 §5, which requires each issuer to sign its own CRL.

The on-demand `GET /crl/der/:issuer_key_id` endpoint already generates per-issuer CRLs correctly via `DerGenerator.generate(issuer_key_id)`.

### Fix

**`CrlPublisher` state change:** replace single `crl_der` field with `%{issuer_key_id => {crl_der, generated_at}}` map.

**`do_generate_crl/0` logic change:**
1. Query all active `IssuerKey` records from Mnesia
2. For each key, call `DerGenerator.generate(issuer_key_id)` — already scopes `CertificateStatus` by `issuer_key_id`
3. Store results in the per-issuer map; skip keys where lease is inactive (log a warning)

**`GET /crl` endpoint change:** update to return a JSON list of `%{issuer_key_id, crl_number, generated_at}` summary entries instead of a single combined CRL blob. Clients needing the DER use `GET /crl/der/:issuer_key_id`.

**Files touched:**
- `src/pki_validation/lib/pki_validation/crl_publisher.ex` — per-issuer generation loop, state map
- `src/pki_validation/lib/pki_validation/api/router.ex` — update `GET /crl` response shape
- `src/pki_validation/test/pki_validation/crl_publisher_test.exs` — per-issuer scoping tests

### Test

Seed two `IssuerKey` records and revoked `CertificateStatus` records belonging to each issuer. Trigger `CrlPublisher.do_generate_crl/0`. Assert:
- Two entries in the CRL state map (one per issuer)
- Each CRL DER contains only its issuer's revoked serials
- The other issuer's revoked serials do not appear

---

## Fix 3 — PostgreSQL Validation Schema Cleanup

### Problem

The `Provisioner` creates `t_<hex>_validation` PostgreSQL schemas at tenant provisioning time (`tenant_validation_schema.sql`). Nothing reads or writes these tables — all validation data is in Mnesia. The `pki_validation` package also has five orphaned Ecto migration files and an `ecto_repos` config entry for a `PkiValidation.Repo` that was never implemented.

### Fix

**Remove from provisioning:**
- `src/pki_platform_engine/lib/pki_platform_engine/provisioner.ex` — remove `apply_tenant_schema_sql("tenant_validation_schema.sql", ...)` from `run_tenant_migrations/1`
- `src/pki_platform_engine/lib/mix/tasks/pki.migrate_existing_tenants.ex` — remove validation schema migration step

**Delete dead files:**
- `src/pki_platform_engine/priv/tenant_validation_schema.sql`
- `src/pki_validation/priv/repo/migrations/` — all 5 migration files

**Remove dead config:**
- `src/pki_validation/config/config.exs` — remove `ecto_repos: [PkiValidation.Repo]`
- `src/pki_platform_engine/lib/pki_platform_engine/tenant_prefix.ex` — remove `validation_prefix/1`, remove `"validation"` from `@valid_prefixes`

**Keep unchanged:** `drop_tenant_schemas` cascade in `Provisioner.delete_schema_mode_tenant/1`. Existing VPS tenants have these schemas; the cascade drop handles them on deletion without any code change.

---

## Documentation Updates

### Full rewrites

**`docs/PKI-System-Technical-Summary.md`**

Replace the old separated-process + PostgreSQL-per-tenant architecture diagram with the current one-BEAM-node-per-tenant model:

```
Internet
    │
    ▼
┌─────────────────────────────────────┐
│  Caddy (80/443)                     │
│  admin.* → pki_platform :4006       │
│  <tenant>.* → pki_tenant (per-node) │
└────────┬────────────────────────────┘
         │
┌────────▼─────────────────────────────────────┐
│  pki_platform BEAM (1 node)                   │
│  Platform portal :4006                        │
│  Tenant lifecycle management                  │
│  PostgreSQL: tenant registry, platform users, │
│              platform audit trail             │
└────────┬─────────────────────────────────────┘
         │  :peer spawn / distributed Erlang
┌────────▼─────────────────────────────────────┐
│  pki_tenant BEAM (one node per tenant)        │
│  CA portal + CA engine (in-process)           │
│  RA portal + RA engine (in-process)           │
│  Validation: OCSP/CRL (in-process)            │
│  State: local Mnesia (disc_copies)            │
└──────────────────────────────────────────────┘
```

Key points to document:
- No HTTP APIs between CA/RA engines and the portals — in-process calls only
- OCSP/CRL served from same tenant BEAM; CDP/OCSP URLs point at tenant subdomain
- Tenant isolation at BEAM process level, not PostgreSQL schema level
- Schema-mode (old) is deprecated

**`README.md`**

Replace old architecture diagram (separate `:4001`/`:4002`/`:4003`/`:4004`/`:4005` processes) with the platform-BEAM + per-tenant-BEAM model. Keep the algorithms table and other non-architecture sections as-is.

### Targeted updates

**`CLAUDE.md`**

Update the Architecture section:
- Remove references to CA Portal / RA Portal / Core CA Engine / RA Engine as independent BEAM processes
- Describe the two-tier model: platform BEAM + per-tenant BEAM
- Note that portals and engines are in the same tenant BEAM (no inter-process HTTP)

**`deploy/DEPLOYMENT.md`**

Remove the "Doc rewrite pending (Milestone 5)" warning banner — the architecture is now stable. Verify the remainder of the guide matches current `deploy/` scripts (no content changes beyond removing the banner, unless inconsistencies are found during review).

**`TODOS.md`**

Move the "Per-tenant schema mode: validation repo wiring" open item to Completed, noting that the architecture moved to Mnesia and the PostgreSQL tables are removed.

---

## Out of Scope

- CDP/OCSP URL embedding in issued certificates (separate initiative)
- CRL pre-signing strategy and refresh orchestration
- `pki_tenant` Phase E dynamic spawning (separate initiative)
