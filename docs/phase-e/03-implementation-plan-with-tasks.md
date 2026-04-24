# Phase E — Implementation Plan with Tasks

This is the **executable plan**. Each task is self-contained: file paths, change details, verification, dependencies. An executor agent (Claude Sonnet) should be able to pick up any task in dependency order and complete it without re-deriving design decisions.

For *why* the design is shaped this way, read [01-adr-hsm-first-key-management.md](./01-adr-hsm-first-key-management.md). For *what* changes from a customer/auditor perspective, read [02-spec-amendment-key-ceremony-v1.1.md](./02-spec-amendment-key-ceremony-v1.1.md).

## Verified file path glossary

| Module | Path |
|---|---|
| CeremonyLive | `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex` |
| CeremonyOrchestrator | `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` |
| KeyActivation | `src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex` |
| ShareEncryption | `src/pki_ca_engine/lib/pki_ca_engine/key_ceremony/share_encryption.ex` |
| KeyCeremony struct | `src/pki_mnesia/lib/pki_mnesia/structs/key_ceremony.ex` |
| IssuerKey struct | `src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex` |
| ThresholdShare struct | `src/pki_mnesia/lib/pki_mnesia/structs/threshold_share.ex` |
| CeremonyTranscript struct | `src/pki_mnesia/lib/pki_mnesia/structs/ceremony_transcript.ex` |
| Auth hook | `src/pki_tenant_web/lib/pki_tenant_web/live/auth_hook.ex` |
| Dispatcher | `src/pki_ca_engine/lib/pki_ca_engine/key_store/dispatcher.ex` |
| OcspResponder | `src/pki_validation/lib/pki_validation/ocsp_responder.ex` |
| CrlPublisher | `src/pki_validation/lib/pki_validation/crl_publisher.ex` |
| CertificateSigning | `src/pki_ca_engine/lib/pki_ca_engine/certificate_signing.ex` |
| Application | `src/pki_ca_engine/lib/pki_ca_engine/application.ex` |

---

## Wave order (execute in this order)

```
WAVE 1 (parallel, no deps): E1.1, E1.2, E1.3, E1.4, E4.1
WAVE 2 (after E1.3):        E1.5, E1.7, E2.1
WAVE 3 (after E1.1):        E1.6
WAVE 4 (after E1.7):        E1.8
WAVE 5 (after E2.1):        E2.2, E3.1, E3.2, E3.3, E5.2
WAVE 6 (after E2.2):        E2.3, E2.4
WAVE 7 (after E2.4):        E2.6
WAVE 8 (after E4.1):        E4.2 (needs E1.1 too), E4.3
WAVE 9 (after E2.4 + E3.x): E5.1
WAVE 10 (cleanup):           E2.5
```

Each task below references its TaskCreate ID from the task list (`#NN`).

---

## Phase E1 — Plumbing & Boot Safety

### E1.1 — Scaffold `CeremonyWitnessLive` (#23)

**Goal**: Stop crashing the auditor flow; give them a real page.

**Files**:
- Read: `src/pki_tenant_web/lib/pki_tenant_web/live/auth_hook.ex:45` (confirms route binding)
- Read: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex` (copy LiveView shape)
- Create: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_witness_live.ex`

**Changes**:
1. Create `PkiTenantWeb.Ca.CeremonyWitnessLive` with `mount/3`, `render/1`.
2. Mount loads ceremony by id from session/params, fetches `KeyCeremony` + `CeremonyParticipant` + `CeremonyTranscript`.
3. Render shows: ceremony status, custodian list with attestation state, transcript event timeline, "Witness ceremony" button.
4. Button records `auditor_witnessed` event via new `CeremonyOrchestrator.record_auditor_witness/3` (placeholder — full signing flow added in E4.2).
5. Add route in CA portal router (find via `grep -rn "live \"/ceremonies" src/pki_tenant_web/lib`).

**Verify**:
- `iex> PkiTenantWeb.Ca.CeremonyWitnessLive.__info__(:functions)` returns `mount/3` and `render/1`.
- Manual: log in as auditor, navigate to ceremony witness page, see the ceremony.

**Depends on**: nothing.
**Estimate**: 4-6 hours.

---

### E1.2 — Boot guard refusing software keystore in prod (#24)

**Goal**: Refuse to start a prod release if any active issuer key has `keystore_type == :software`.

**Files**:
- Read: `src/pki_ca_engine/lib/pki_ca_engine/application.ex` (find existing `assert_dev_activate_safe!` — extend that pattern).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/application.ex`.

**Changes**:
1. Add `assert_no_software_keystore_in_prod!/0` next to `assert_dev_activate_safe!`.
2. Logic: if `Application.get_env(:pki_ca_engine, :env) == :prod` AND `Application.get_env(:pki_ca_engine, :allow_software_keystore_in_prod, false) == false`, query Mnesia for `IssuerKey{status: "active", keystore_type: :software}`. If any found, raise.
3. Call from `Application.start/2` next to existing dev_activate guard.
4. Allow opt-out for migration period via `:allow_software_keystore_in_prod` config flag (defaults `false`).

**Verify**:
- New unit test: `test/pki_ca_engine/application_test.exs` with two cases (allow=false raises, allow=true boots).
- `MIX_ENV=prod PKI_ENABLE_PROD=true mix run -e ...` with a software issuer key in Mnesia → expect crash.

**Depends on**: nothing.
**Estimate**: 3 hours.

---

### E1.3 — Add `keystore_mode` field to ceremony wizard (#25)

**Goal**: User can pick `software`, `softhsm`, or `hsm` at ceremony initiation.

**Files**:
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/key_ceremony.ex` (add `:keystore_mode` to `@fields`, lines 4-5).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (`initiate/2` accepts `:keystore_mode`, persists into `KeyCeremony`).
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex` (`initiate_ceremony` form: add radio for `keystore_mode`).

**Changes**:
1. Add `keystore_mode :: String.t()` to `KeyCeremony` struct, valid values `["software", "softhsm", "hsm"]`.
2. Default `"softhsm"` if not provided.
3. `CeremonyOrchestrator.initiate/2` validates: in `:prod` env, only `"hsm"` allowed; raise otherwise.
4. `IssuerKey.keystore_type` derives from `KeyCeremony.keystore_mode` at activation time.
5. LiveView: add radio buttons in initiate modal, hide `software` option when `Mix.env() == :prod`.
6. Pre-condition check: if `keystore_mode = "hsm"`, verify a configured HSM keystore exists; else `{:error, :no_hsm_keystore_configured}`.

**Verify**:
- Unit test: `KeyCeremony.new(%{keystore_mode: "softhsm"})` round-trips.
- Unit test: `CeremonyOrchestrator.initiate(%{keystore_mode: "software"}, env: :prod)` raises.
- Manual: initiate ceremony in dev, see all 3 options; in test config, see `softhsm` default.

**Depends on**: nothing.
**Estimate**: 4 hours.

---

### E1.4 — External-cert activation for pending sub-CA-of-external-root (#38)

**Goal**: Spec lines 220-228 — when CA setup is "Sub CA rooted to external root", a CSR is generated, key marked "pending", external CA returns cert, system uploads cert and activates the key.

**Files**:
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (add `activate_with_external_cert/3`).
- Create: a new LiveView page or extend existing IssuerKey detail page with "Upload external cert" form.

**Changes**:
1. UI to upload external cert (PEM or DER) for a pending `IssuerKey`.
2. Validation: cert chains to declared external root, public key matches the pending key's pub key, validity dates sane, signature algorithm matches.
3. On valid: store cert, flip `IssuerKey.status` `pending → active`, write audit event `key_activated_with_external_cert`.
4. On invalid: error with specific reason (chain validation, pubkey mismatch, expired, algo mismatch).

**Verify**:
- Test: matching cert activates the key.
- Test: wrong public key rejected with `:public_key_mismatch`.
- Test: expired cert rejected with `:cert_expired`.
- Test: mismatched algo rejected with `:algo_mismatch`.

**Depends on**: nothing (uses existing pending-key flow).
**Estimate**: 1 day.

---

### E1.5 — Auto-spawn sub-CA after self-signed root completes (#39)

**Goal**: Spec lines 218-219 — "Immediately after [self-signed root], a sub-CA keypair and certificate shall be generated. Sub-CA keypair and certificate shall be marked 'active'."

**Files**:
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (`execute_keygen` post-success path).

**Changes**:
1. **First**: grep `CeremonyOrchestrator` + tests to determine if current code already auto-spawns sub-CA. If YES: add explicit test asserting sub-CA exists+active after root ceremony, then close task.
2. If NO: extend `execute_keygen` post-success to:
   - Generate sub-CA keypair via `Dispatcher` in same HSM.
   - Sub-CA cert signed by the just-completed root key (still in HSM lease window).
   - Flip both `IssuerKey` rows active.
3. Sub-CA gets its own ceremony record (lighter — same custodians authorized by lease).

**Verify**:
- Test: full root ceremony → assert root active AND sub-CA active.
- Test: sub-CA cert chain validates against root cert.

**Depends on**: E1.3 (needs `keystore_mode`).
**Estimate**: 1 day.

---

### E1.6 — Enforce auditor presence as ceremony pre-condition (#40)

**Goal**: Spec line 193 — "Multiple Key Managers AND at least one auditor is required to activate this process."

**Files**:
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (`initiate/2`).
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_witness_live.ex` (add accept flow).

**Changes**:
1. `CeremonyOrchestrator.initiate/2` validates `auditor_user_id` ∈ tenant users with role `auditor`; raises `{:error, :auditor_required}` otherwise.
2. Auditor must accept ceremony invitation via `CeremonyWitnessLive` before `initiate` completes (status `awaiting_auditor_acceptance`).
3. Once auditor clicks "Accept and witness", ceremony moves to `preparing`.
4. Audit log `auditor_accepted` event.
5. Wire the existing-but-unused `verify_identity/2` function (orchestrator.ex:184).

**Verify**:
- Test: no auditor registered → initiate fails with `:auditor_required`.
- Test: non-auditor user → fails.
- Test: valid auditor accepts → ceremony proceeds to `preparing`.

**Depends on**: E1.1.
**Estimate**: 6 hours.

---

### E1.7 — Three-mode keygen (`threshold | password | single_custodian`) (#41)

**Goal**: Spec line 249 (Issuer Key Management): "Generate of key (threshold on private key, password OR solely by custodian)".

**Files**:
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex` (add `:key_mode` field).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (branch by mode).

**Changes**:
1. Add `:key_mode` field to `IssuerKey` struct, values `"threshold" | "password" | "single_custodian"`.
2. Update `CeremonyOrchestrator`:
   - `threshold`: existing flow.
   - `password`: skip Shamir split, derive key encryption from a single password set by Key Manager (PBKDF2).
   - `single_custodian`: same as password but UI labels as single-officer key.
3. Each mode persists differently in `ThresholdShare` table (n=1 for password/single, n>=2 for threshold).
4. Activation logic must branch identically.

**Verify**:
- Test: each mode end-to-end (init → keygen → activation → sign).
- Test: `n=1, k=1` for non-threshold modes.

**Depends on**: E1.3.
**Estimate**: 1.5 days.

---

### E1.8 — Single-custodian guardrails (#42)

**Goal**: Hard product-safety rules around lighter `key_mode` options from E1.7.

**Files**:
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex` (add `:key_role` field).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (validation).
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex` (UI banner).
- Modify: `src/pki_audit_trail/lib/...` (audit event enrichment).

**Changes**:
1. Add `:key_role` to `IssuerKey`: `"root" | "issuing_sub" | "operational_sub"`.
2. Orchestrator validates `key_role == "root" AND key_mode != "threshold"` → `{:error, :root_requires_threshold}`.
3. UI: when `key_mode in ("password", "single_custodian")` selected, show banner: *"This mode does not meet WebTrust §6.2.2 dual-control. Use only for internal/private CAs."*
4. Audit log: every cert signed by a `single_custodian`/`password` key emits a `low_assurance_signing` event with elevated severity.
5. Cert metadata: include CPS reference noting activation mode in the issued cert's policies extension (configurable).
6. Default `key_mode = "threshold"` in UI to nudge customers toward the safe option.

**Verify**:
- Test: `root + password` → reject.
- Test: `sub-CA + single_custodian` + UI render shows banner.
- Test: cert issued by `single_custodian` generates the audit event.

**Depends on**: E1.7.
**Estimate**: 1 day.

---

## Phase E2 — Lease-Based Activation

### E2.1 — Refactor `KeyActivation` from key bytes to lease handle (#26)

**Goal**: `KeyActivation` no longer holds private key bytes; holds opaque session handle + lease metadata.

**Files**:
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex`.
- Create: `test/pki_ca_engine/key_activation_lease_test.exs`.

**Changes**:
1. Replace `active_keys :: %{key_id => private_key_der}` with `active_leases :: %{key_id => lease_record}`.
2. `lease_record :: %{handle: term, expires_at: DateTime.t, ops_remaining: integer, custodians: [String.t]}`.
3. New API:
   - `activate(key_id, [%{custodian, auth_token}], opts)` — returns `{:ok, lease_id}` or `{:error, reason}`.
   - `with_lease(key_id, fun)` — passes handle to `fun`, decrements `ops_remaining`, fails if expired.
   - `lease_status(key_id)` — returns `%{active: bool, expires_in: seconds, ops_remaining: int}`.
4. Keep legacy `submit_share/4` and `get_active_key/2` as **deprecated shims** routing to the new flow.
5. Lease defaults: `4h timeout`, `100 ops`, configurable via `:pki_ca_engine, :lease_defaults`.

**Verify**:
- Test: activate → use 100 times → 101st returns `{:error, :ops_exhausted}`.
- Test: activate → wait past timeout → `lease_status` shows `active: false`.
- Test: `with_lease` decrements ops correctly.
- Test: existing `submit_share` tests still pass (shim is wired).

**Depends on**: E1.3.
**Estimate**: 1.5 days.

---

### E2.2 — Build `ActivationCeremony` module + `ActivationSession` struct (#27)

**Goal**: Encapsulates "k custodians authenticated → lease granted" state machine, separate from key generation.

**Files**:
- Create: `src/pki_ca_engine/lib/pki_ca_engine/activation_ceremony.ex`.
- Create: `src/pki_mnesia/lib/pki_mnesia/structs/activation_session.ex`.
- Create: `test/pki_ca_engine/activation_ceremony_test.exs`.

**Changes**:
1. `ActivationCeremony.start/2` opens a new activation session, status `awaiting_custodians`.
2. `ActivationCeremony.submit_auth/4` handles k-of-n custodian authentication (SoftHSM: PIN+Shamir share verify; HSM: card+PIN verify).
3. When threshold met: calls `KeyStore.Dispatcher.authorize_session(issuer_key_id, auth_tokens)`; on success, `KeyActivation.activate/3` with the returned handle.
4. `ActivationCeremony.cancel/2` for early termination.
5. Persist `ActivationSession` to Mnesia for audit trail.

**Verify**:
- Test: 2-of-3 ceremony with all 3 custodians submitting → lease granted.
- Test: 2-of-3 ceremony with only 1 custodian → status stays `awaiting_custodians`.
- Test: wrong PIN → `{:error, :authentication_failed}`, custodian not counted.
- Integration test (SoftHSM): full flow `start → 2 submit_auth → lease active → sign cert → ops decremented`.

**Depends on**: E2.1.
**Estimate**: 2 days.

---

### E2.3 — `ActivationLive` page (#28)

**Goal**: User-facing page for the activation ceremony.

**Files**:
- Create: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/activation_live.ex`.
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/live/auth_hook.ex` (add `PkiTenantWeb.Ca.ActivationLive` to allowed modules).
- Add route in router.

**Changes**:
1. List view: all `IssuerKey`s with lease status (active/expired, ops remaining, expires in).
2. Detail view per key: "Start activation ceremony" button.
3. Activation modal: same slot-based custodian entry as existing `CeremonyLive` (reuse the modal component).
4. Live updates: when lease state changes, `Phoenix.PubSub` broadcasts.
5. Show "Lease expires in: 3h 24m | 87 ops left" prominently.

**Verify**:
- Manual: open in browser, start activation, k custodians submit, lease shown active.
- Manual: wait for lease to expire, page auto-updates to show expired.

**Depends on**: E2.2.
**Estimate**: 1.5 days.

---

### E2.4 — SoftHSM adapter implements `authorize_session` callback (#29)

**Goal**: Use SoftHSM's token PIN as the post-threshold authentication artifact.

**Files**:
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_store/dispatcher.ex` (add callback to behaviour).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_store/softhsm_adapter.ex` (implement).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_store/software_adapter.ex` (compat shim).

**Changes**:
1. Add `@callback authorize_session(key_id, [auth_tokens]) :: {:ok, session_handle} | {:error, reason}` to keystore behaviour.
2. SoftHSM adapter: derive token PIN deterministically from k authenticated custodian shares (e.g., `:crypto.hash(:sha256, sorted_shares) |> Base.encode16 |> binary_part(0, 16)`); call `softhsm2-util --login`.
3. Software adapter: returns the reconstructed key as the "handle" (preserves backward compat).
4. Dispatcher routes `authorize_session/2` to the right adapter based on `issuer_key.keystore_type`.

**Verify**:
- Integration test: SoftHSM-backed `IssuerKey`, full activation ceremony, then `Dispatcher.sign(...)` works inside lease.
- Test: 3 authenticated custodians produce same session handle on retry (deterministic).

**Depends on**: E2.2.
**Estimate**: 1 day.

---

### E2.5 — Cleanup deprecated `KeyActivation` shims (#30)

**Goal**: After E2.1-E2.4, the deprecated shims in `KeyActivation` can be removed.

**Files**:
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex`.

**Changes**:
1. Remove `submit_share/4` and `get_active_key/2` if no callers remain (run `grep -rn "submit_share\|get_active_key" src/`).
2. Or keep gated by `allow_dev_activate`-style escape hatch.

**Verify**:
- Full test suite passes.
- `grep -rn "submit_share\|get_active_key" src/` returns only the deprecated shims (or empty).

**Depends on**: E2.1-E2.4.
**Estimate**: 4 hours.

---

### E2.6 — Isolate custodian PIN handling (#43)

**Goal**: Mitigate plaintext-passwords-in-LiveView-socket gap from earlier audit.

**Files**:
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex` (lines 131, 557).
- Create: `src/pki_tenant_web/lib/pki_tenant_web/ca/custodian_pin_vault.ex`.

**Changes**:
1. Replace `entered_passwords` map in socket assigns with a short-lived GenServer (`CustodianPinVault`) that holds PINs in process state with explicit zeroize on use.
2. LiveView submits PIN to vault → gets back a token; LiveView holds token, vault holds PIN.
3. `execute_keygen` calls `vault.consume(token)` → PIN returned once, then nil'd + GC.
4. Vault dies (and GCs) at end of ceremony regardless of success/failure.
5. Document in module `@moduledoc` that on real HSM PED hardware (Phase E5+) the host never sees PIN at all.

**Verify**:
- Test: vault deletes PIN after `consume`.
- Test: vault dies on ceremony complete.
- Test: double-consume returns `:already_consumed`.

**Depends on**: E2.4.
**Estimate**: 1 day.

---

## Phase E3 — Signing Path Hardening

### E3.1 — `OcspResponder` fail-closed without active lease (#31)

**Goal**: OCSP returns `tryLater` (RFC 6960 §2.3) instead of silently signing with a software key.

**Files**:
- Modify: `src/pki_validation/lib/pki_validation/ocsp_responder.ex` (`signed_response/3`).

**Changes**:
1. Before calling `Dispatcher.sign(...)`, check `KeyActivation.lease_status(issuer_key_id)`.
2. If `active: false`: return `{:ok, %{status: :try_later, ...}}`.
3. If `active: true`: wrap call in `KeyActivation.with_lease(issuer_key_id, fn handle -> Dispatcher.sign_with_handle(handle, ...) end)`.
4. Update docstring to note fail-closed behavior.

**Verify**:
- Unit test: no lease → returns `tryLater`.
- Unit test: active lease → returns signed response, ops decremented.
- Existing OCSP tests still pass.

**Depends on**: E2.1.
**Estimate**: 4 hours.

---

### E3.2 — `CrlPublisher` `crl_strategy` (#32)

**Goal**: Per-interval (requires lease) or pre-signed (sign N future CRLs at ceremony, store, serve).

**Files**:
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/issuer_key.ex` (add `:crl_strategy`).
- Modify: `src/pki_validation/lib/pki_validation/crl_publisher.ex`.
- Create: `src/pki_validation/lib/pki_validation/crl_pre_sign.ex`.
- Create: `src/pki_mnesia/lib/pki_mnesia/structs/pre_signed_crl.ex`.

**Changes**:
1. Add `crl_strategy` to `IssuerKey` (default `"per_interval"`).
2. `CrlPublisher.publish/1` checks strategy:
   - `per_interval`: requires active lease; fails closed.
   - `pre_signed`: looks up next valid CRL from new Mnesia table `PreSignedCrl{issuer_key_id, valid_from, valid_until, crl_der}`.
3. New `CrlPreSign.generate_batch/3` — at ceremony close, sign N future CRLs, store.

**Verify**:
- Test: `per_interval` + no lease → `{:error, :no_active_lease}`.
- Test: `pre_signed` + valid CRL exists for current time → returns it.
- Test: `pre_signed` + no valid CRL → `{:error, :no_valid_pre_signed_crl}`.

**Depends on**: E2.1.
**Estimate**: 1 day.

---

### E3.3 — Prometheus metrics for HSM lease state (#33)

**Goal**: Operators can monitor lease state across all tenant issuer keys.

**Files**:
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_activation.ex` (emit `:telemetry` events).
- Modify: wherever Prometheus exporter is wired (likely `pki_platform_engine` per Phase C work).

**Changes**:
1. Emit `:telemetry.execute([:pki_ca_engine, :key_activation, :lease], %{ops_remaining: N, expires_in: S}, %{key_id: id})` on activate/use/expire.
2. Add Prometheus gauges:
   - `pki_hsm_session_active{issuer_key_id, tenant_id}` (0/1).
   - `pki_hsm_session_ops_remaining{issuer_key_id, tenant_id}`.
   - `pki_hsm_session_expires_in_seconds{issuer_key_id, tenant_id}`.
3. Add `:telemetry_metrics_prometheus` config entry.

**Verify**:
- Curl `/metrics` endpoint, see new gauges.
- Activate ceremony, see `pki_hsm_session_active` flip to 1.

**Depends on**: E2.1.
**Estimate**: 4 hours.

---

## Phase E4 — Cryptographic Transcript

### E4.1 — Hash-chained `CeremonyTranscript` entries (#34)

**Goal**: Tamper-evident transcript; each entry includes hash of previous entry.

**Files**:
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/ceremony_transcript.ex`.
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (every entry-append site).

**Changes**:
1. Add `prev_hash :: binary()` and `event_hash :: binary()` fields (mirror existing `audit_events`).
2. New `CeremonyTranscript.append/2` helper computes `event_hash = sha256(prev_hash || event_payload)`.
3. Genesis entry: `prev_hash = <<0::256>>`.
4. Add `verify_chain/1` function: walks entries, checks `event_hash` matches recompute.

**Verify**:
- Test: append 5 entries, `verify_chain` returns `:ok`.
- Test: tamper with entry 3's payload, `verify_chain` returns `{:error, {:broken_at, 3}}`.

**Depends on**: nothing.
**Estimate**: 1 day.

---

### E4.2 — Auditor signs transcript with own key (#35)

**Goal**: Independent attestation beyond ink signatures.

**Files**:
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/ceremony_transcript.ex` (add `auditor_signature`, `auditor_public_key`, `signed_at`).
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_witness_live.ex` (add "Sign transcript" flow).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (add `record_auditor_signature/3`).

**Changes**:
1. Auditor uploads their public key at ceremony start (or pre-registered as `CeremonyParticipant`).
2. At close: portal computes transcript digest, displays QR code with digest + ceremony id.
3. Auditor signs digest with their offline key, uploads signature.
4. Portal verifies against registered public key, persists.
5. `CeremonyTranscript.verify_auditor_signature/1` recomputes + verifies.

**Verify**:
- Test: register pubkey at start, sign digest at close, verify passes.
- Test: signature with wrong key → `verify` returns `{:error, :invalid_signature}`.

**Depends on**: E4.1, E1.1.
**Estimate**: 1.5 days.

---

### E4.3 — Sign each encrypted share (#44)

**Goal**: Spec NFR — "Mission-critical encryption must be digitally signed."

**Files**:
- Modify: `src/pki_mnesia/lib/pki_mnesia/structs/threshold_share.ex` (add `:share_signature`).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/ceremony_orchestrator.ex` (sign during keygen).
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_ceremony/share_encryption.ex` (verify during decrypt).

**Changes**:
1. At ceremony close, system signs each encrypted_share blob with a ceremony-scoped signing key (or the issuer key itself if already active).
2. `ThresholdShare` gets new field `:share_signature`.
3. On reconstruction, verify signature BEFORE attempting decrypt — fail fast on tampered/swapped envelopes.
4. Custodian-side standalone verifier tool: a small CLI/Elixir script that takes (share, public_key) and verifies the signature offline.

**Verify**:
- Test: tampered share fails verify.
- Test: swapped envelope fails verify.
- Test: valid share verifies + decrypts.

**Depends on**: E4.1.
**Estimate**: 1 day.

---

## Phase E5 — Tests

### E5.1 — Integration test: SoftHSM-backed full lifecycle (#36)

**Goal**: End-to-end test of the new flow.

**File**: `test/integration/hsm_full_lifecycle_test.exs`.

**Covers**: ceremony with `keystore_mode: "softhsm"` → activation ceremony → cert sign via Dispatcher → OCSP signed response → CRL publish.

**Depends on**: E2.1-E2.4, E3.1, E3.2.
**Estimate**: 1 day.

---

### E5.2 — Property tests for `KeyActivation` lease state machine (#37)

**Goal**: Random-sequence verification of lease invariants.

**File**: `test/pki_ca_engine/key_activation_property_test.exs` (using `StreamData`).

**Invariants**: lease never resurrects after expire; `ops_remaining` monotonically non-increasing within lease; concurrent `with_lease` calls don't double-spend ops; deactivate is idempotent.

**Depends on**: E2.1.
**Estimate**: 4 hours.

---

## Final readiness checklist

| Check | Status |
|---|---|
| All audit findings have a task or are explicitly out-of-scope | Done |
| All spec functional requirements have a task | Done |
| All spec NFRs covered (encryption, signing, audit logging, multi-person control) | Done |
| Dev/test path doesn't require new hardware | Done |
| Backward compat with shipped Phase D BYOK-HSM | Done |
| Boot guards prevent accidental prod misuse | Done |
| WebTrust-grade default behavior, opt-down explicit | Done |
| Test strategy covers happy path + failure modes | Done |

**Total estimate**: ~16-18 days of focused engineering, $0 hardware cost.

---

## Out-of-scope (acknowledged, not in this plan)

| Item | Why deferred |
|---|---|
| Cert renewal flow (spec line 254) | Phase F — keystore-agnostic |
| Configure keypair access UI (spec line 296) | Existing schema; UI work |
| Real smart-card m-of-n (PED keys) | Phase E6 — Luna/nShield hardware purchase |
| HSM cloning ceremony for DR backup HSM | Phase E6 — same hardware blocker |
| WebTrust audit submission | Post-pilot |
| Mnesia transaction retry/back-off (audit gap #5) | Low impact, ops feedback |
