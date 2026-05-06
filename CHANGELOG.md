# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/), versioning follows
`MAJOR.MINOR.PATCH.MICRO` (4-digit).

## [1.1.4.0] - 2026-05-07

### Added

- **SoftHSM2 PKCS#11 local-HSM ceremony path** — Full end-to-end key generation
  ceremony support using a local SoftHSM2 token via the existing `Pkcs11Port` C
  port. `LocalHsmAdapter.generate_key/3` drives `C_GenerateKeyPair` for ECC-P256,
  ECC-P384, RSA-2048, and RSA-4096; private keys never leave the token.
  `SofthsmPinCustody` wraps and unwraps per-tenant user/SO PINs with AES-256-GCM
  using an HKDF-SHA256 DEK derived from the platform master key, binding ciphertext
  to `tenant_id` in both the HKDF `info` and AES-GCM AAD to prevent cross-tenant
  envelope reuse. `CeremonyOrchestrator` now handles `keystore_mode: "softhsm"`
  exactly like a real HSM: no Shamir shares are created, `execute_keygen/2` accepts
  an empty password list, and the resulting `IssuerKey` has `keystore_type: :local_hsm`
  with a fully-populated `hsm_config` including `key_label`, `key_id` (CKA_ID hex),
  `library_path`, `slot_id`, and `pin`.

- **CA portal ceremony wizard — HSM bypass flow** — When `keystore_mode` is
  `"softhsm"` or `"hsm"`, the wizard no longer enters the custodian slot-entry
  phase. After a successful `initiate`, it fires `:execute_keygen` immediately
  (no vault, no custodian tokens), displays an in-progress banner, and transitions
  directly to the completed/pending state. The keystore dropdown is now optional
  (only required for hardware HSM mode); the "New Key Ceremony" button is enabled
  for all CA instances regardless of registered keystores.

- **SoftHSM2 integration test suite** — `softhsm_keygen_test.exs` in
  `pki_ca_engine` (tagged `@moduletag :softhsm`, excluded from default CI run).
  Tests: low-level `LocalHsmAdapter` generate + sign + verify for ECC-P256 and
  RSA-2048 against a real `libsofthsm2.so`; full root CA ceremony producing a
  self-signed certificate; full sub-CA ceremony producing a CSR (status `"pending"`).
  Run with `mix test --include softhsm test/integration/softhsm_keygen_test.exs`.

## [1.1.3.0] - 2026-05-06

### Added

- **Test coverage across four packages** — 158 net-new tests across
  `pki_mnesia` (38% → 72%), `pki_ra_engine` (49% → 54%), `pki_platform_engine`
  (24% → 28%), and `pki_tenant_web` (9% → 20%). Covers 19+ Mnesia struct
  constructors and validators, Ecto changeset validation logic, DcvVerifier
  SSRF-blocked domain paths, DateLogHandler OTP callbacks, SystemHealth metrics
  helpers, CA portal LiveView lifecycle events for certificates and issuer keys,
  and full mount smoke tests for all CA and RA portal pages.

### Fixed

- **`certificates_live.ex` revoke clause ordering** — the catch-all
  `handle_event("revoke_cert", _params, ...)` clause was defined before the
  specific `%{"serial" => ..., "reason" => ...}` pattern, making the specific
  clause unreachable. Clause order corrected so revocations with valid params
  are processed correctly rather than silently dropped.

## [1.1.2.0] - 2026-05-06

### Added

- **Test coverage for validation service hardening** — `CrlPublisher.status/1`
  is now tested (structure, `generation_error` flag, per-issuer `issuer_count`);
  `signed_crl/2` guard paths tested (`issuer_key_not_active`,
  `issuer_key_not_found`); `ResponseBuilder.build/4` error-status nonce path
  verified via ASN.1 decode across all four error statuses (`unauthorized`,
  `tryLater`, `internalError`, `malformedRequest`).

## [1.1.1.0] - 2026-04-26

### Fixed

- **HSM gateway WebSocket listener wired** — `HsmGateway` now starts a Cowboy
  listener when `HSM_GATEWAY_PORT` is set. Production mode requires mTLS
  (`HSM_GATEWAY_CERTFILE/KEYFILE/CACERTFILE`); dev falls back to plaintext
  with a loud warning; production without certs refuses to boot.
  `terminate/2` now fires for all exit signals (trap_exit added) so the
  listener is always cleaned up on crash or supervisor kill.
- **PKCS#11 session serialized in Go agent** — `HsmClient` gains
  `sync.Mutex`; `ListKeyLabels`, `Sign`, and `AvailableKeyLabels` all hold
  it. Sign requests now drain through a single worker goroutine via a
  buffered channel (cap 64) instead of spawning unbounded goroutines — fixes
  concurrent PKCS#11 session access which is undefined behavior.
- **`MechanismForAlgorithm` returns error for unknown algorithms** — the Go
  agent previously fell back to `CKM_ECDSA` for any unrecognized algorithm,
  including PQC keys. It now returns `(0, false)` so callers can reject the
  request cleanly rather than risk key misuse on a misbehaving HSM.
- **HSM agent-id binding at signing time** — `RemoteHsmAdapter.key_available?`
  now cross-checks `hsm_config["expected_agent_id"]` against the connected
  agent when the field is set, preventing a rogue or misconfigured agent from
  being used to sign with a key intended for a specific registered agent.
- **Legacy Ecto code confirmed retired** — `SyncCeremony`, `AsyncCeremony`,
  `Schema.*`, `Repo`, `TenantRepo` were deleted in M4c (2026-04-20).
  TODOS.md now reflects this.

## [1.1.0.0] - 2026-04-19

Ships the per-tenant BEAM architecture (Phase A), multi-host Mnesia
replication (Phase B), operational readiness (Phase C), and BYOK-HSM
(Phase D) as a single merge to main.

### Added

**Per-tenant BEAM + Mnesia data layer (Phase A)**
- `pki_mnesia` app — 16 struct definitions, schema versioning, CRUD Repo.
- `pki_tenant` and `pki_tenant_web` apps — a tenant engine that owns its
  own supervision tree, endpoint, and Mnesia tables. Host-based routing
  serves the CA portal, RA portal, and OCSP endpoint from the same tenant
  node on per-tenant hostnames.
- All 11 LiveView portals migrated from PG-backed Ecto to tenant-scoped
  Mnesia. Shared auth, session store, layouts, and DaisyUI + heroicons assets.
- `pki_platform_engine` — platform-level services: tenant lifecycle,
  Caddy configurator, port allocator, tenant health monitor, audit receiver.
- CA engine, RA engine, and validation engine rewritten against Mnesia.
- `mix migrate_pg_to_mnesia` task for one-shot data migration from an
  existing PG deployment.
- Two new OTP releases: `pki_platform` and `pki_tenant_node`.

**Multi-host replication (Phase B)**
- `PkiMnesia.Schema.add_replica_copies/1`, `promote_to_primary/0`,
  `demote_to_replica/1` — handle cluster joins and role changes.
- `pki_replica` app — ClusterMonitor, FailoverManager, PortAllocator,
  TenantReplicaSupervisor.
- `PkiTenant.MnesiaBootstrap` gains a replica branch that joins a
  primary node (`PRIMARY_TENANT_NODE` env var) instead of initializing
  fresh schema.
- `libcluster` topology configuration + `pki_replica` release for the
  standby node.

**Operational readiness (Phase C)**
- `BackupRecord` struct + schema: every Mnesia backup is tracked in
  Mnesia itself.
- `PkiTenant.Health` module with JSON `/health` endpoints on tenant and
  platform webs.
- `S3Upload` + daily `MnesiaBackup` scheduler — encrypts and uploads
  backups to S3 on a cron.
- `CaddyConfigurator` writes a 3-hostname Caddy config (ca, ra, ocsp per
  tenant) and dispatches OCSP requests to the right tenant node.
- `Caddyfile.template` + `deploy/RESTORE.md` runbook.
- Phoenix LiveDashboard mounted on both tenant and platform webs for
  real-time observability.

**BYOK-HSM (Phase D)**
- `PkiCaEngine.KeyStore` behaviour with `sign/2`, `get_public_key/1`,
  `key_available?/1`. Dispatcher routes by `IssuerKey.keystore_type`.
- Three adapters: `SoftwareAdapter` (existing, zero-change default),
  `LocalHsmAdapter` (PKCS#11 over an Erlang port to a C binary),
  `RemoteHsmAdapter` (WebSocket to an off-host Go agent).
- `pkcs11_port.c` — a C port binary that loads any `.so` via dlopen and
  performs sign / get_public_key / ping commands. Handles vendor-defined
  mechanism codes for KAZ-SIGN and ML-DSA. Signature buffer uses the
  two-call PKCS#11 pattern to scale to post-quantum signature sizes.
- `hsm-agent/` — a statically-linked Go binary that speaks WebSocket to
  the backend and PKCS#11 to the HSM. Supports YubiKey, Entrust, Thales
  Luna, SafeNet, SoftHSM2, or any PKCS#11 device. mTLS 1.3 required.
- `HsmGateway` + `AgentHandler` WebSocket server. Bearer-token
  authentication with constant-time comparison and key-label allowlisting
  per agent.
- `MockHsmAdapter` for tests and local dev without real hardware.
- `scripts/setup-softhsm-test.sh` and `scripts/test-hsm-flow.exs` for
  full flow testing against SoftHSM2.

**Test infrastructure**
- Root `config/test.exs` + `config/config.exs` import loader so a single
  `mix test` at the repo root runs all root-level integration tests.
- Root `test/test_helper.exs` with sensible exclusions (`:softhsm`,
  `:pqc_nif`, `:hsm_hardware` tags).

### Changed

- `CertificateSigning`, `OcspResponder`, and `CrlPublisher` route signing
  through `KeyStore.Dispatcher.sign/2` instead of calling
  `PkiCaEngine.KeyActivation` directly.
- HSM agent transport is WebSocket + JSON (not gRPC as the spec
  originally called for). The proto file in `priv/proto/hsm_gateway.proto`
  is retained as protocol documentation.
- Legacy engine apps (`pki_ca_engine`, `pki_ra_engine`, `pki_validation`,
  `pki_audit_trail`, `pki_platform_engine`) now honor a per-app
  `start_application` config flag so they can coexist with the tenant
  supervision tree without conflicting on named registries.

### Security

- **HSM gateway agent authentication (pre-landing review P0 fix):** the
  agent handler now requires a bearer `auth_token` that is verified
  with constant-time comparison against a configured allowlist. Each
  entry binds agent_id, tenant_id, and allowed key_labels. Fails closed
  when no allowlist is configured, unless `:hsm_agent_allow_any` is
  explicitly set (dev-only).
- **Agent mTLS required (pre-landing review P0 fix):** the Go agent no
  longer silently falls back to plaintext when TLS config is missing.
  Client cert, client key, and backend CA cert are all mandatory; any
  missing piece is a fatal config error.
- **Signature verification on HSM responses (pre-landing review P0 fix):**
  `RemoteHsmAdapter.sign/3` now verifies every signature returned by
  the agent against the issuer key's stored public key before returning
  it. A compromised agent cannot inject attacker-chosen bytes.
- **PKCS#11 port buffer overflow (pre-landing review P0 fix):** C_Sign
  response buffer was a fixed 4 KiB on the stack, which overflowed on
  post-quantum signatures. Switched to the two-call PKCS#11 pattern
  with a 10 MiB upper bound.

### Known limitations

- PG-dependent legacy engine tests require a running Postgres at
  localhost:5434. Run `./scripts/init-databases.sh` against a local
  postgres instance before `./scripts/test-all.sh`.
- Real two-server HSM integration test against actual HSM hardware is
  deferred — current coverage uses MockHsmAdapter and SoftHSM2.
- Windows HSM agent build is not yet produced — only macOS and Linux.
- HSM wizard UI is deferred — configure via IEx / config for now.

[1.1.0.0]: https://github.com/antrapolation/pki/compare/v1.0.0-beta.3...v1.1.0.0
