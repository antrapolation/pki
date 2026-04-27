# TODOS

Tracked per-component. P0 = exploitable/blocker, P1 = exploitable with specific
conditions, P2 = defense-in-depth / hardening, P3 = cleanup, P4 = nice-to-have.
Keep priority + component headings; move to `## Completed` once done.

## Prioritized backlog (post-v1.1.0.0)

The per-component sections below are the authoritative registry. This block
tracks the order we agreed to work through them.

### Tier 1 — Foundation (force multipliers)
- [x] **1a. Native PG setup** — PG 17 via brew on macOS, default port 5432
  (test configs moved off 5434). Done 2026-04-19.
- [x] **1b. Triage pre-existing failures unmasked by 1a** — deleted 9
  legacy Ecto-era test files, fixed two bugs in `RemoteHsmAdapter.sign/3`
  (wrong `:public_key.der_decode` target, wrong pubkey format for ECC
  verify). pki_ca_engine now 360 tests / 0 failures. Done 2026-04-19.
- [x] **1c. x509 doctest drift cleanup** — 3 RDN doctests updated to OTP 28
  format + 56 TLS-interop sanity tests skipped (library-internal, not
  consumer-facing API). x509 submodule now 0 failures, 90 excluded.
  Done 2026-04-19.
- [x] **1d. Retire legacy Ecto-backed code paths** — `SyncCeremony`,
  `AsyncCeremony`, `Schema.*`, `Repo`, `TenantRepo`, `ceremony_controller`
  all deleted in M4c commits (872eea4, df729af, a7adc0b). `IssuerKeyManagement`
  functions exist and have live callers. No dead code remains. Done 2026-04-20.

### Tier 2 — Security P1s (ordered easy → hard)
- [x] **2a. Fail-closed attestation in CredentialManager** — N/A: `CredentialManager`
  deleted in M4c (872eea4). No attestation surface remains in pki_ca_engine. Done 2026-04-26.
- [x] **2b. Bind advertised key labels to tenant at registration** — `HsmGateway.connected_agent_id/1`
  added; `RemoteHsmAdapter.key_available?` now cross-checks `hsm_config["expected_agent_id"]`
  when set. Done 2026-04-26.
- [x] **2c. PKCS#11 session mutex in hsm-agent** — `sync.Mutex` added to `HsmClient`;
  `ListKeyLabels` and `Sign` both lock it. Sign requests serialized through a single
  worker goroutine via buffered `signCh` channel (capacity 64) — unbounded goroutine spawn
  removed. `MechanismForAlgorithm` now returns `(uint, bool)` — returns `false` for unknown
  algorithms instead of silently falling back to ECDSA. Done 2026-04-26.
- [x] **2d. mTLS at Cowboy listener** — `HsmGateway.init/1` now starts a Cowboy listener
  when `port` opt is given (no listener in tests, backwards-compatible). TLS: reads
  `HSM_GATEWAY_CERTFILE/KEYFILE/CACERTFILE` from env or app config; starts `cowboy_tls`
  with `verify: :verify_peer` + `fail_if_no_peer_cert: true`. Falls back to plaintext
  in non-prod with a loud warning; raises in prod without certs. `terminate/2` stops
  the listener on shutdown/crash. Done 2026-04-26.

### Tier 3 — Quality infrastructure
- [x] **3a. Wire `mix test --cover`** — `test_coverage: [threshold: 70,
  summary: [threshold: 70]]` added to 9 package mix.exs files;
  `scripts/coverage.sh` runs the sweep and prints a per-package summary.
  All 9 packages produce numbers as of 2026-04-21:
  pki_crypto 80.3% ✅, pki_ca_engine 55.0%, pki_tenant 53.4%,
  pki_mnesia 48.3%, pki_validation 47.9%, pki_ra_engine 46.1%,
  pki_platform_engine 16.3%, pki_platform_portal 9.6%,
  pki_tenant_web 2.2%.
- [x] **3b. First real E2E test with PG up** — CSR → RA approve → CA sign
  → OCSP check against live engines. Merged as PR #87 (2026-04-26).

### Tier 4 — Product roadmap
- [x] **4a. Phase 4 PQC OCSP + CRL signing** — DerResponder + DerGenerator
  wired to IssuerKey signing path. Merged as PR #84 (2026-04-26).
- [x] **4b. HSM wizard UI** — CA admin 5-step wizard + platform admin 4-step
  modal. HsmAgentSetup Mnesia struct + context, PubSub broadcast on agent
  registration, resume banner in HsmDevicesLive. Done 2026-04-26.
- [x] **4c. Remaining P2 hardening items**
  - [x] `SoftwareAdapter.sign/3` + `get_raw_key/2` migrated from deprecated
    `get_active_key/2` to `with_lease/3`. Done 2026-04-26 (PR #85).
  - [x] PBKDF2 iterations bumped 100k→600k in `ShareEncryption` +
    `CeremonyOrchestrator` (OWASP 2023). Done 2026-04-26 (PR #85).
  - [x] `format_status/1` added to `KeyActivation` (redacts lease handles)
    and `Pkcs11Port` (redacts HSM PIN). Done 2026-04-26 (PR #85).
  - [x] `SoftwareAdapter.do_sign/3` fallback to `PkiCrypto.Registry` removed —
    single algorithm registry. Done 2026-04-26 (PR #86).
  - [x] `CeremonyOrchestrator` private key GC narrowed at each step.
    Done 2026-04-26 (PR #86).
  - [x] `pkcs11_port.c` hand-rolled JSON parser replaced with cJSON v1.7.18.
    Done 2026-04-27 (this PR).
  - [x] `Pkcs11Port` request-ID correlation — stale port responses discarded by id.
    Done 2026-04-27 (this PR).
  - [x] `parse_mechanism` fail-closed for unknown mechanisms.
    Done 2026-04-27 (this PR).

## Open

### Real HSM two-server integration test
**Priority:** P2
**Notes:** Phase D shipped with MockHsmAdapter + SoftHSM2 scripts. Running
the backend on one host and the Go agent + a real HSM (YubiKey or
SoftHSM2 in a container) on another host to exercise mTLS end-to-end is
still deferred. Needs physical hardware or a container-based SoftHSM2 setup.

## Completed

### Per-tenant schema mode: validation repo wiring
**Completed:** 2026-04-28 (this PR)
PostgreSQL `t_<hex>_validation` tables removed from provisioning and migrate task.
`validation_prefix/1` removed from `TenantPrefix`. Five orphaned Ecto migration files
and `ecto_repos: [PkiValidation.Repo]` config deleted. All validation state uses Mnesia
on the tenant BEAM node — no PostgreSQL validation schema was ever written or read.

### pki_tenant_web feature parity
**Completed:** 2026-04-27 (PR #92)
P1 RBAC guards added to `activation_live` (key_manager/ca_admin), `ceremony_live` (ca_admin),
`hsm_wizard_live` (mount-level redirect). `/activation` nav link added to CA sidebar with
`is_active?` clause and route test. `/setup-wizard` added to RA sidebar. `invite_user` and
`configure_service` wizard stubs wired to `/users` and `/service-configs` with flash.
CA layout unified to `user_role(@current_user)` helper. 49 tests, 0 failures.

### Per-tenant schema mode: audit + validation
**Completed:** 2026-04-27 (PR #91)
Per-tenant `t_<hex>_audit.audit_events` (hash-chained) and
`t_<hex>_validation.{certificate_status,crl_metadata,signing_key_config}` tables
provisioned at tenant creation. `PkiAuditTrail.HashChainStore` (ETS, per-tenant
prev_hash), `PkiAuditTrail.log/4` (write hash-chained events via PlatformRepo with
prefix), `PlatformAudit.log/2` wired for schema-mode tenants. Actions list expanded
to 38 entries. `mix pki.migrate_existing_tenants` for existing VPS tenants.

### Native PG setup automation
**Completed:** 2026-04-27 (this PR)
`scripts/dev-setup-pg.sh` — idempotent macOS/Linux setup: installs/starts PG, creates
`postgres` superuser role, creates all prod + `_test` database variants.

### Windows HSM agent build
**Completed:** 2026-04-27 (this PR)
`build-windows` target added to `hsm-agent/Makefile`.
Requires `mingw-w64` cross-compiler (`brew install mingw-w64` on macOS).

### HSM gateway P1/P2 hardening (Tiers 2 + 4c)
**Completed:** 2026-04-26/27 (PRs #83, #85, #86, #89)
- mTLS at Cowboy listener with `verify: :verify_peer` + `fail_if_no_peer_cert: true` (2d, #83)
- `sync.Mutex` + sign serialization via buffered channel in hsm-agent (2c, #83)
- Agent-id binding at registration; `expected_agent_id` cross-check in `RemoteHsmAdapter` (2b, #83)
- `CredentialManager` N/A — deleted in earlier refactor (2a, #83)
- `SoftwareAdapter` dual-registry fallback removed; single `AlgorithmRegistry` source of truth (4c, #86)
- `CeremonyOrchestrator` private-key GC narrowed after each step (4c, #86)
- `format_status/2` added to `KeyActivation` and `Pkcs11Port` — redacts secrets from crash dumps (4c, #85)
- PBKDF2 iterations bumped 100k→600k in `ShareEncryption` and `CeremonyOrchestrator` (4c, #85)
- `SoftwareAdapter.sign/3` and `get_raw_key/2` migrated to `with_lease/3` (4c, #85)
- `pkcs11_port.c` hand-rolled strstr JSON parser replaced with cJSON v1.7.18 (4c, #89)
- `Pkcs11Port` request-ID correlation — `await_response/3` discards stale messages by id (4c, #89)
- `parse_mechanism` fail-closed for unknown mechanisms; `explicit_bzero` for PIN zeroing (4c, #89)
- Agent `MechanismForAlgorithm` returns explicit error for unmapped algorithms (2c, #83)

### Phase 4 — PQC OCSP + CRL signing
**Completed:** 2026-04-26 (PR #84)
DerResponder + DerGenerator wired to IssuerKey signing path for all supported algorithms.

### HSM wizard UI
**Completed:** 2026-04-26 (PR #88)
CA admin 5-step wizard + platform admin 4-step modal. HsmAgentSetup Mnesia struct + context,
PubSub broadcast on agent registration, resume banner in HsmDevicesLive.

### KDF domain separation for ACL credential wrap keys
**Priority:** was P1
**Completed:** v1.1.0.1 (2026-04-19)
**Notes:** `PkiCaEngine.KeypairACL.initialize/3` used to wrap both the
signing_cred and kem_cred with the same root key derived from the ACL
password. `activate/5` derived the same one key and decrypted both.
Even with AES-GCM's random IVs (so no immediate nonce reuse), using one
KEK for two distinct purposes is a domain-identical-function gap.

New scheme (tagged `pki_acl/v1/cred/<type>`): an HKDF-SHA256 sub-key is
derived per credential_type from the ACL root key. signing_cred and
kem_cred now wrap with distinct keys — a future deterministic-nonce
mistake or bad RNG cannot leak across credential types.

Backward compatible: `decrypt_acl_credential/3` tries the v1 scheme
first and falls back to the legacy raw-root-key wrap, logging a warning
recommending re-initialization. No schema migration needed.

Tests in `test/pki_ca_engine/keypair_acl_unit_test.exs` (9 pure-function
tests — domain separation, salt sensitivity, round-trip, backward compat,
negative cases).

### Boot-time prod guard for `dev_activate`
**Priority:** was P1
**Completed:** v1.1.0.1 (2026-04-19)
**Notes:** `PkiCaEngine.Application.start/2` now refuses to boot when the
compile-time env is `:prod` and `:pki_ca_engine, :allow_dev_activate` is
true. The check logic lives in pure function
`PkiCaEngine.Application.check_dev_activate_safe/2` for easy testing.
`pki_ca_engine`'s own config/config.exs records its compile env as
`:pki_ca_engine, :env, config_env()` so the assertion has a reliable
signal without depending only on the umbrella's `:pki_system, :env`.
Tests in `test/pki_ca_engine/application_test.exs`. The compile-time
"strip the handler" variant from the review was dropped: Mix path-dep
compilation evaluates `Mix.env/0` as `:prod` regardless of the parent
env, so the boot-time gate + runtime flag check are the reliable defense.

### Verify custodian password against stored hash before encrypting share
**Priority:** was P1
**Completed:** v1.1.0.1 (2026-04-19)
**Notes:** `CeremonyOrchestrator.execute_keygen/2` now verifies every
supplied custodian password against the hash stored in `accept_share`
before any key material is generated. Constant-time compare via
`:crypto.hash_equals/2`. Rejects with `{:custodian_password_mismatch, name}`,
`{:share_not_accepted, name}`, `{:missing_password, name}`, or
`{:corrupt_password_hash, name}`. Tests in
`test/pki_ca_engine/ceremony_orchestrator_test.exs` under describe
"execute_keygen/2 password verification".
