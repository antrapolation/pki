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
- [ ] **1b. Triage pre-existing failures unmasked by 1a** — pki_ca_engine now
  compiles + runs 525 tests, 161 fail. Failures look like real API drift
  (e.g. `IssuerKeyManagement.create_issuer_key/3` called but only `/2`
  exists). Not caused by recent PRs; accumulated during the Mnesia rewrite.
  Need a dedicated triage pass before P1 work continues.
- [ ] **1c. x509 doctest drift cleanup** — 59 noise failures will hide real
  regressions. Effort: ~30min.

### Tier 2 — Security P1s (ordered easy → hard)
- [ ] **2a. Fail-closed attestation in CredentialManager** (~1h)
- [ ] **2b. Bind advertised key labels to tenant at registration** (~2h)
- [ ] **2c. PKCS#11 session mutex in hsm-agent** (~2h)
- [ ] **2d. mTLS at Cowboy listener** (~4-8h)

### Tier 3 — Quality infrastructure
- [ ] **3a. Wire `mix test --cover`** — real line-coverage numbers. Target
  ≥70% for pki_ca_engine / pki_ra_engine / pki_crypto.
- [ ] **3b. First real E2E test with PG up** — CSR → RA approve → CA sign
  → OCSP check against live engines.

### Tier 4 — Product roadmap
- [ ] **4a. Phase 4 PQC OCSP + CRL signing** (multi-day)
- [ ] **4b. HSM wizard UI** (1-2 days)
- [ ] **4c. Remaining P2 hardening items** (see per-component sections)

## HSM gateway (Phase D)

### mTLS at the Cowboy listener
**Priority:** P1
**Notes:** v1.1.0.0 ships bearer-token auth + constant-time compare for the
HSM agent handler. The production-grade defense in depth is mTLS at the
Cowboy listener (`verify: :verify_peer` + `cacertfile`) so bad certs never
reach the handler at all. Then bind `agent_id` to the cert subject instead
of trusting the body.

### Sync.Mutex + worker pool for HSM agent PKCS#11 session
**Priority:** P1
**Source:** pre-landing review (confidence 7/10)
**Notes:** `hsm-agent/ws_client.go:127` spawns an unbounded goroutine per
sign_request, and `hsm-agent/pkcs11.go` does `FindObjects/SignInit/Sign`
on the same session from concurrent goroutines. PKCS#11 sessions are not
thread-safe — concurrent operations on one session are undefined behavior.
Add a `sync.Mutex` around HSM operations and a bounded worker pool.

### Bind agent's advertised key labels to tenant at registration
**Priority:** P1
**Source:** pre-landing review (confidence 7/10)
**Notes:** `RemoteHsmAdapter.key_available?/2` trusts
`HsmGateway.available_keys/1`, which is self-reported by the agent during
register. v1.1.0.0 adds allowlist-based label checking in `authenticate_agent`
(labels must be a subset of the agent's configured `key_labels`), but the
runtime adapter still trusts the gateway's cached list. Cross-check the
advertised labels against `IssuerKey.hsm_config.expected_agent_id`.

### Fail-closed attestation in CredentialManager
**Priority:** P1
**Source:** pre-landing review (confidence 6/10)
**Notes:** `PkiCaEngine.CredentialManager.verify_credential_attestation/N`
returns `:ok` when `certificate` or `attested_by_key` is nil with only a
log warning. Fail closed: require attestation for all non-bootstrap
credentials.

### Replace hand-rolled JSON parser in pkcs11_port.c
**Priority:** P2
**Source:** pre-landing review (confidence 9/10 — JSON bug is small
surface in practice because input is from the trusted BEAM port driver,
but still ugly and brittle.)
**Notes:** `json_get_string` is a `strstr`-based parser with no escape
handling. Link against jansson or cJSON. Keep the current stack-allocated
label/pin buffers in mind; they silently truncate at 256 bytes.

### Single source of truth for algorithm registry in SoftwareAdapter
**Priority:** P2
**Source:** pre-landing review (confidence 7/10)
**Notes:** `PkiCaEngine.KeyStore.SoftwareAdapter.do_sign/N` falls back to
`PkiCrypto.Registry.get/1` if `AlgorithmRegistry.by_id/1` returns `:error`.
Two registries, one authoritative — they could disagree on algorithm
semantics for the same identifier. Consolidate to one.

### Correlate port requests by ID in Pkcs11Port
**Priority:** P2
**Source:** pre-landing review (confidence 6/10)
**Notes:** `PkiCaEngine.KeyStore.Pkcs11Port.send_command/N` uses a bare
`receive do {^port, {:data, data}}` inside handle_call. A stale response
from a previous (crashed and restarted) port can pile up in the mailbox.
Add request-id correlation.

### Redact secrets in GenServer state via format_status/2
**Priority:** P2
**Source:** pre-landing review (confidence 6/10)
**Notes:** `PkiCaEngine.KeyActivation` stores reconstructed raw secrets in
`state.active_keys[id].secret`. `PkiCaEngine.KeyStore.Pkcs11Port` stores
the HSM PIN in `state.pin`. `:sys.get_state/1` and crash dumps will include
these. Implement `format_status/2` to replace sensitive values with
`:redacted`.

### Narrow raw private-key lifetime in CeremonyOrchestrator
**Priority:** P2
**Source:** pre-landing review (confidence 6/10)
**Notes:** `CeremonyOrchestrator` calls `:erlang.garbage_collect()` after
split, but `decode_private_key` / `self_sign` / `Csr.generate` all touch
the raw `priv` binary. Narrow the scope and GC after each step.

### Agent `MechanismForAlgorithm` fallback to ECDSA
**Priority:** P2
**Source:** pre-landing review (confidence 6/10)
**Notes:** `hsm-agent/pkcs11.go:146-157` returns `CKM_ECDSA` for any
unknown algorithm including PQC. If a tenant requests "ML-DSA-65" and the
agent doesn't know the mechanism, it asks the HSM to do ECDSA with an
ML-DSA key — either hard error or, on misbehaving HSMs, key misuse. Return
an explicit error for unmapped algorithms.

### Increase ShareEncryption PBKDF2 iterations
**Priority:** P2
**Source:** pre-landing review (confidence 5/10)
**Notes:** `PkiCaEngine.KeyCeremony.ShareEncryption` uses 100k PBKDF2-SHA256
iterations. OWASP 2023 guidance is 600k for SHA-256, or switch to Argon2id
which is already in the dep tree.

## Test infrastructure

### Native PG setup automation
**Priority:** P3
**Notes:** Local dev setup is manual today:

- macOS: `brew install postgresql@17 && brew services start postgresql@17`
  (default port 5432). Create a `postgres` superuser role with password
  `postgres`, then create databases: `pki_{ca_engine,ra_engine,validation,
  audit_trail,platform}` and their `_test` counterparts.
- Linux: system package + systemd, same shape.

Nice-to-have: `scripts/dev-setup-pg.sh` that wraps the flow
idempotently, and a `make test` wrapper that verifies PG is reachable
before invoking `mix test`. Current `scripts/init-databases.sh` is
container-specific and only creates prod databases, not `_test`.

### Real HSM two-server integration test
**Priority:** P2
**Notes:** Phase D shipped with MockHsmAdapter + SoftHSM2 scripts. Running
the backend on one host and the Go agent + a real HSM (YubiKey or
SoftHSM2 in a container) on another host to exercise mTLS end-to-end is
still deferred.

## Deployment

### Windows HSM agent build
**Priority:** P3
**Notes:** `hsm-agent` is only built for macOS and Linux. Windows support
needs a cross-compile target in the Makefile plus PKCS#11 library-path
discovery for Windows HSM vendors.

### HSM wizard UI
**Priority:** P3
**Notes:** Today HSM adapters are configured via IEx or config files.
A LiveView wizard — pick adapter, test connection, import public key —
would make BYOK-HSM practical for the RA portal's day-2 flow.

## Roadmap

### Phase 4: PQC OCSP + CRL signing
**Priority:** P1
**Notes:** Cross-algo cert signing (Phases 1-3) landed earlier. PQC OCSP
responses and CRL signing are still unbuilt. Tracked separately in memory
under `project_cross_algo_signing`.

### Per-tenant schema mode: audit + validation
**Priority:** P2
**Notes:** Schema-mode VPS deployment shipped 2026-04-15; per-tenant audit
log and validation service still use the shared-PG path. Tracked in memory
under `project_schema_mode_outstanding`.

## Completed

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
