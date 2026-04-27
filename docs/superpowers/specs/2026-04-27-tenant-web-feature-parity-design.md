# pki_tenant_web Feature Parity — Design Spec

**Date:** 2026-04-27
**Scope:** CA portal + RA portal in `pki_tenant_web`

---

## Goal

Verify that every LiveView in `pki_tenant_web` (27 pages across CA + RA portals) fully wires up to its backend: no stub handlers, no references to non-existent modules, no mismatched function arities. Produce a prioritised gap table, implement all P1/P2 fixes, then validate the 7 critical user flows at runtime.

The legacy `pki_ca_portal` and `pki_ra_portal` (Ecto-backed) were deleted in Tier 1d. `pki_tenant_web` is the sole tenant-facing portal; it must reach production completeness before any customer-facing rollout.

---

## Architecture

`pki_tenant_web` is a multi-tenant Phoenix LiveView app that uses host-based routing to serve `ca.<tenant>.<domain>` (CaRouter) and `ra.<tenant>.<domain>` (RaRouter). All state is in Mnesia via the tenant's BEAM node — no Ecto/Postgres calls from portal code.

Auth is handled by `PkiTenantWeb.Live.AuthHook` on every live session. Backend calls go through:
- **CA portal** → `PkiCaEngine.*` + `PkiTenant.*` context modules
- **RA portal** → `PkiRaEngine.*` + `PkiTenant.*` context modules
- **Shared** → `PkiTenant.AuditTrail`, `PkiTenant.PortalUserAdmin`

---

## Audit Scope

### CA Portal LiveViews (14 files)

| File | Lines | Description |
|------|-------|-------------|
| `ca/live/dashboard_live.ex` | 344 | Engine status summary |
| `ca/live/ca_instances_live.ex` | 495 | Create / rename / activate / suspend CA instances |
| `ca/live/ceremony_live.ex` | 1652 | Full key ceremony wizard (initiate → generate → distribute → complete) |
| `ca/live/ceremony_custodian_live.ex` | 473 | Custodian share acceptance |
| `ca/live/ceremony_witness_live.ex` | 593 | Auditor witness + transcript signing |
| `ca/live/activation_live.ex` | 623 | Issuer key unlock / lease grant |
| `ca/live/issuer_keys_live.ex` | 965 | Key lifecycle (suspend / reactivate / retire) |
| `ca/live/certificates_live.ex` | 834 | Issued certificates (view / revoke / download) |
| `ca/live/hsm_devices_live.ex` | 212 | HSM agent list + resume banner |
| `ca/live/hsm_wizard_live.ex` | 669 | 5-step HSM onboarding wizard |
| `ca/live/keystores_live.ex` | 326 | Keystore CRUD |
| `ca/live/users_live.ex` | 24 | Thin wrapper → `UsersLiveShared` |
| `ca/live/audit_log_live.ex` | 24 | Thin wrapper → `AuditLogLiveShared` |
| `ca/controllers/ceremony_transcript_controller.ex` | — | Printable transcript (plain controller) |

### RA Portal LiveViews (13 files)

| File | Lines | Description |
|------|-------|-------------|
| `ra/live/dashboard_live.ex` | 619 | CSR queue stats + engine status |
| `ra/live/ra_instances_live.ex` | 311 | RA instance CRUD |
| `ra/live/ca_connection_live.ex` | 361 | CA connection management |
| `ra/live/csrs_live.ex` | 628 | CSR list + approve / reject + in-portal submit |
| `ra/live/cert_profiles_live.ex` | 752 | Certificate profile CRUD |
| `ra/live/certificates_live.ex` | 330 | Issued certificate list + revoke |
| `ra/live/api_keys_live.ex` | 690 | API key CRUD |
| `ra/live/service_configs_live.ex` | 223 | OCSP / CRL / TSA endpoint config |
| `ra/live/setup_wizard_live.ex` | 1094 | RA onboarding wizard |
| `ra/live/validation_status_live.ex` | 246 | Live OCSP + CRL health check |
| `ra/live/users_live.ex` | 24 | Thin wrapper → `UsersLiveShared` |
| `ra/live/audit_log_live.ex` | 24 | Thin wrapper → `AuditLogLiveShared` |
| `ra/live/welcome_live.ex` | 84 | First-boot redirect / setup CTA |

### Shared Components (4 files)

| File | Description |
|------|-------------|
| `live/audit_log_live_shared.ex` | Shared audit log render + filter + export |
| `live/users_live_shared.ex` | Shared user management render + CRUD |
| `live/profile_live.ex` | User profile (username / display name / email / password) |
| `live/auth_hook.ex` | Auth on-mount hook for all live sessions |

---

## Audit Dimensions

For each LiveView, check:

1. **Stub detection** — `# TODO`, `raise "not implemented"`, empty `handle_event` clauses returning `{:noreply, socket}` without action, or placeholder renders ("Coming soon", blank templates).
2. **Module existence** — every `alias` target module exists in the codebase (grep for `defmodule`). Flag any alias that resolves to a deleted or renamed module.
3. **Function signature match** — each backend call `Module.function/arity` exists at the called arity. Special attention to context modules that changed during Phase A–D refactors.
4. **Nav completeness** — every `sidebar_link` in `layouts.ex` points to a live route that exists; every routed LiveView has a corresponding nav entry (or is intentionally nav-less like wizard steps).
5. **RBAC guards** — every mutating `handle_event` checks `current_user[:role]` or delegates to a role-aware context; no admin action callable by auditor role.

---

## Gap Triage

Findings classified as:

- **P1** — blocks a critical user flow (broken module ref, wrong arity, auth guard missing on mutating action)
- **P2** — feature gap (stub handler that silently no-ops, missing UI action for a backend operation that exists)
- **P3** — polish (nav label mismatch, dead nav entry, missing loading state)

Fixes will be batched: P1s first, then P2s, then P3s. Each batch gets its own commit.

---

## Critical Paths for Runtime Validation

After gap fixes are applied, these 7 flows are verified against a live local tenant:

| # | Flow | Portal | Steps |
|---|------|--------|-------|
| 1 | Root key ceremony | CA | Create CA instance → configure software keystore → initiate ceremony → supply custodian passwords → generate key |
| 2 | Key activation | CA | Navigate to Activation → unlock issuer key with custodian passwords → confirm active lease |
| 3 | HSM wizard (if agent available) | CA | Connect Go agent → step through 5-step wizard → key appears in HSM Devices list |
| 4 | CSR → signed cert | RA + CA | Submit CSR via RA portal → RA officer approves → CA signs → cert visible in both portal certificate lists |
| 5 | Cert revocation | CA | Revoke cert with reason → OCSP lookup returns revoked status |
| 6 | Audit log reads | CA + RA | Perform a mutation → event appears in audit log with correct actor and category |
| 7 | User lifecycle | CA + RA | Create user → log in as new user → admin suspends → admin reactivates |

Any failure during runtime validation is treated as a P1 regression and fixed before the branch is merged.

---

## Out of Scope

- Per-tenant PostgreSQL audit table surfacing in the portal audit log — the audit log reads from Mnesia (`PkiTenant.AuditTrail`) and that is intentional for now; wiring the hash-chained PG audit to the portal is a separate initiative
- DCV challenge management page — RA engine has DCV logic but no portal page; deferred
- ML-DSA / SLH-DSA key ceremony UI differences — algorithm-specific extensions deferred
- `pki_platform_portal` — out of scope; this spec covers only `pki_tenant_web`
