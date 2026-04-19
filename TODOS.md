# TODOS

Tracked per-component. P0 = exploitable/blocker, P1 = exploitable with specific
conditions, P2 = defense-in-depth / hardening, P3 = cleanup, P4 = nice-to-have.
Keep priority + component headings; move to `## Completed` once done.

## HSM gateway (Phase D)

### mTLS at the Cowboy listener
**Priority:** P1
**Notes:** v1.1.0.0 ships bearer-token auth + constant-time compare for the
HSM agent handler. The production-grade defense in depth is mTLS at the
Cowboy listener (`verify: :verify_peer` + `cacertfile`) so bad certs never
reach the handler at all. Then bind `agent_id` to the cert subject instead
of trusting the body.

### Per-credential salt + HKDF domain separation in KeypairACL
**Priority:** P1
**Source:** pre-landing review (confidence 8/10)
**Notes:** `PkiCaEngine.KeypairACL.initialize/3` derives one ACL key with
`iterations: 1` and uses it to encrypt both `signing_cred` and `kem_cred`
with the same salt. Even with a random GCM nonce this is a defense-in-depth
gap — different credentials should derive distinct keys via HKDF with a
domain-separation tag.

### Compile-time prod guard for `dev_activate`
**Priority:** P1
**Source:** pre-landing review (confidence 7/10)
**Notes:** `PkiCaEngine.KeyActivation.dev_activate/2` is gated only on
`Application.get_env(:pki_ca_engine, :allow_dev_activate, false)`. A
misconfigured prod release that accidentally sets the flag enables a
threshold bypass. Add `if Mix.env() != :prod do ... else raise end`
at module compile time, and hard-fail at boot if the flag is true in prod.

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

### Native PG setup docs for umbrella-root tests
**Priority:** P2
**Notes:** `mix test` at the repo root runs 16 Mnesia-backed integration
tests cleanly. PG-backed legacy engine tests (`pki_ca_engine`,
`pki_ra_engine`, `pki_platform_engine`, portals) need Postgres running on
localhost:5434. Bare metal all the way: no Docker.

- macOS dev: `brew install postgresql@16 && brew services start postgresql@16`
  then `./scripts/init-databases.sh`. The script creates the 5 databases
  on whichever port PG is listening on — ensure the `pg_ctl` config uses
  5434, or set `PGPORT=5434` in shell profile.
- Linux dev/prod: same system package + systemd that prod deploys with.

Add a `scripts/dev-setup-pg.sh` that wraps the brew / apt flow with port
check + database init, and a `make test` wrapper that verifies PG is up
before invoking `mix test`.

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
