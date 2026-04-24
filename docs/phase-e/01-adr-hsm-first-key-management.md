# ADR-001: HSM-First Key Management

| Status | Date | Authors | Reviewers |
|---|---|---|---|
| Accepted | 2026-04-24 | PKI Engineering | Pending |

## Context

The PKI system currently supports two keystore types:

1. **Software keystore** (default for new ceremonies): Shamir-split private key, each share AES-256-GCM encrypted with a custodian's password, key reconstructed in BEAM process memory at activation time.
2. **HSM keystore** (Phase D shipped): PKCS#11 dispatcher, key generated and used inside HSM, never extracted.

**Problem 1 — production safety.** The software keystore reconstructs raw private key bytes inside the BEAM process at every signing operation. This violates:

- CA/Browser Forum Baseline Requirements §6.2.7 (Root + Sub CA keys must be in FIPS 140-2 Level 3 / CC EAL 4+ modules).
- WebTrust for CAs Principle 2 (cryptographic module standards).
- The product's own security NFR ("password to activate private key shall be encrypted to specific officer and not via system blanket approval") — a key in process RAM is, transitively, a system-blanket-approved key.

A WebTrust audit (Baker Tilly, KPMG, Deloitte) of a publicly-trusted CA running this configuration would result in a critical finding leading to root program removal. Empirical research found **no publicly-trusted CA whose published CPS lists software-keystore-with-USB-shares as the production custody model**.

**Problem 2 — custodian artifact.** The current model has each custodian leave the ceremony with their share as a file (encrypted with their password). A USB stick is trivially clonable; an attacker who obtains a custodian's stick has unlimited offline brute-force capability against the password. A FIPS Level 3 smart card is not clonable — extraction attempts trigger tamper response and zeroize the card. Real CAs (ICANN root KSK, Let's Encrypt, DigiCert et al.) universally use FIPS-validated smart cards for custodian artifacts, not commodity USB media.

**Problem 3 — the "single custodian" requirement.** The product spec v1.0 allows sub-CAs to be operated by a single Key Manager without multi-party ceremony. This is **acceptable for internal/private PKI** (enterprise device fleets, internal mTLS) but **fails WebTrust** for sub-CAs intended for public trust stores. The product needs to support both customer segments without compromising the safety of the WebTrust path.

**Problem 4 — keystone code already exists.** Phase D (BYOK-HSM) shipped a `KeyStore.Dispatcher` abstraction with software, SoftHSM, and PKCS#11 adapters. Most of the architecture for HSM-first is already implemented. The remaining work is making HSM-first the **default** rather than the opt-in.

## Decision

**1. HSM-first architecture.** The system defaults to HSM-backed keys. Software keystore is demoted to a developer/test-only mode, refused at boot in any production environment.

**2. Lease-based activation, not per-operation reconstruction.** When a key is activated, the HSM grants a leased session (default: 4 hours, 100 operations). All signing operations within the lease window route through the HSM session handle, not through reconstructed key bytes. The lease semantics are explicit, observable, and bounded.

**3. Three key generation modes for non-root keys.**
- `threshold` — k-of-n custodian shares, full ceremony (REQUIRED for root keys, default for sub-CAs)
- `password` — single Key Manager with a password (sub-CAs only)
- `single_custodian` — single Key Manager identified by name (sub-CAs only)

Non-threshold modes display a warning that they do not meet WebTrust §6.2.2 dual-control requirements and are intended for internal/private CAs.

**4. Auditor is a ceremony quorum participant.** The auditor must be registered AND must accept the ceremony invitation before key generation can begin. The existing-but-unused `verify_identity/2` orchestrator function is wired in.

**5. Cryptographic transcript signing.** The ceremony transcript becomes hash-chained (mirroring the existing `audit_events` pattern) and is signed at close by the auditor's own keypair. The printed transcript with ink signatures is preserved as a redundant attestation.

**6. Signed-share envelopes.** Each encrypted share is additionally signed with a system signing key, so a custodian can independently verify their share is authentic before attempting decryption. Addresses the spec NFR "mission-critical encryption must be digitally signed" beyond AEAD.

**7. Boot-time guards.** Production releases refuse to start if any active `IssuerKey` has `keystore_type = :software` (mirrors the existing `dev_activate` guard pattern).

## Alternatives considered

### A1: Keep software keystore as the default; add HSM as opt-in
**Rejected.** Defaults matter. A default that fails WebTrust will accidentally ship to a customer who needs WebTrust. Make the safe path easy and the unsafe path explicit.

### A2: Drop software keystore entirely
**Rejected.** Developers need to run ceremonies on a laptop without HSM hardware. Boot guard solves the production safety problem without removing developer ergonomics.

### A3: Reconstruct key inside HSM only (no BEAM process holding bytes), but keep custodian USB-file artifact
**Partially adopted.** The "key never in BEAM" requirement is decided. The custodian artifact stays as a SoftHSM PIN-derived stand-in until real smart-card hardware lands in Phase E5+. We document the gap; we do not pretend it is closed.

### A4: Force k-of-n for all keys including sub-CAs
**Rejected.** The product spec explicitly allows lighter modes for sub-CAs. Many enterprise PKI customers (the majority of likely buyers) prefer single-officer sub-CAs for operational reasons. Force-them is a worse outcome than warn-them.

### A5: Build new HSM abstraction from scratch
**Rejected.** Phase D shipped a working `Dispatcher` 4 months ago. Reusing it preserves shipped functionality and concentrates Phase E work on the higher-value ceremony/lease/activation layers.

## Consequences

### Positive

- WebTrust audit-ready architecture; eliminates the largest known finding category.
- Defense in depth: AEAD + signature on shares; hash chain + signature on transcript; lease-bounded HSM session; per-officer encryption preserved.
- Clear product positioning: enterprise PKI customers can use lighter modes with explicit risk acknowledgement; commercial public-trust customers get the safe default.
- Backward compatible with shipped Phase D HSM work — no existing code paths break.
- $0 hardware cost for development; new hardware is a procurement item, not a code blocker.

### Negative

- Two-mode complexity (software for dev, HSM for prod) requires careful boot-time and config-time guards.
- SoftHSM stand-in does not eliminate plaintext PIN handling on the host — fully closed only when real PED hardware lands in Phase E5+.
- Deprecates existing `KeyActivation.submit_share/4` and `get_active_key/2` APIs — shimmed for backward compatibility, removed in E2.5.
- New `key_role` and `key_mode` fields require a Mnesia schema migration for existing tenants.
- Hardware procurement timeline (Nitrokey HSM 2, Thales Luna) is on the critical path for first pilot customer launch.

### Neutral

- Existing software-keystore tenants in pre-production environments continue to work; production opt-in via `:allow_software_keystore_in_prod` flag during migration window.

## References

- Research briefing on real-world CA ceremony practices (in conversation transcript, 2026-04-24)
- Code audit of current key ceremony flow (in conversation transcript, 2026-04-24)
- Product Spec v1.0 (`docs/Product.Spec-PQC.CA.System-v1.0.docx`)
- Phase D BYOK-HSM PR #1 (shipped 2026-04-19)
- ICANN DNSSEC Root KSK DPS: https://www.iana.org/dnssec/procedures/ksk-operator/ksk-dps-20201104.html
- CA/Browser Forum Baseline Requirements: https://cabforum.org/working-groups/server/baseline-requirements/requirements/
- WebTrust for CAs Principles & Criteria v2.2.1
- ETSI EN 319 411-1
- Mozilla Root Store Policy v3.0
