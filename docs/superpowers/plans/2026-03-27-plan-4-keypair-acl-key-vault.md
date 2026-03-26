# Keypair ACL + Key Vault — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Keypair ACL system and Key Vault that provide cryptographic access control for keypair activation. The ACL is a special system credential that gates access to operational keypairs via signed grant envelopes.

**Architecture:** The Keypair ACL is a credential with signing + KEM keypairs. When a keypair is created with credential-owned protection, its activation password is encrypted with the ACL's KEM public key. Access is granted by creating signed grant envelopes. The Key Vault manages keypair registration and grant lifecycle.

**Tech Stack:** Elixir, PkiCrypto (Algorithm, Symmetric, Kdf), Ecto

**Spec:** `docs/superpowers/specs/2026-03-26-beta2-multi-tenancy-crypto-credentials.md` Sections 4, 5

**Depends on:** Plan 3 (Credential Manager) — completed

---

## File Structure

```
src/pki_ca_engine/lib/pki_ca_engine/
├── keypair_acl.ex                    — ACL credential management
├── key_vault.ex                      — keypair registration + grant management
├── key_vault/
│   ├── managed_keypair.ex            — Ecto schema for managed keypairs
│   └── keypair_grant.ex              — Ecto schema for access grants
└── credential_manager/
    └── attestation.ex                — public key signing/attestation
```

---

### Task 1: Create ManagedKeypair and KeypairGrant schemas + migrations

Managed keypair schema: stores keypairs with their encrypted activation passwords.
Keypair grant schema: stores signed access grants per user.

### Task 2: Implement KeypairACL module

Creates and manages the special ACL credential. Provides:
- `initialize(admin_user_id, admin_password)` — creates the ACL credential
- `activate(admin_user_id, admin_password)` — decrypts ACL signing + KEM keys
- `is_initialized?()` — checks if ACL exists

### Task 3: Implement Key Vault

Manages keypair registration and grants:
- `register_keypair(keypair_data, protection_mode, opts)` — registers with ACL
- `grant_access(keypair_id, credential_id, admin_session)` — creates signed grant
- `verify_grant(keypair_id, credential_id)` — verifies a user has access
- `activate_keypair(keypair_id, user_session)` — two-level decryption via ACL

### Task 4: Implement three protection modes

- `:credential_own` — password encrypted with ACL's KEM key
- `{:split_auth_token, required}` — password split via Shamir, shares to custodians
- `{:split_key, required}` — private key itself split, shares to custodians

### Task 5: Implement Attestation module

Public key signing by the creating admin:
- `attest_public_key(admin_signing_key, target_public_key)` — signs the target's public key
- `verify_attestation(admin_public_key, attestation, target_public_key)` — verifies

### Task 6: Integration tests

End-to-end flow:
1. Create admin with credentials
2. Initialize ACL
3. Register a keypair with credential-owned protection
4. Grant access to a user
5. User activates keypair via two-level hierarchy
6. User signs data with the activated keypair

---

## Plan Summary

| Task | What | Tests |
|------|------|-------|
| 1 | ManagedKeypair + KeypairGrant schemas | ~10 tests |
| 2 | KeypairACL module | ~8 tests |
| 3 | Key Vault | ~10 tests |
| 4 | Three protection modes | ~12 tests |
| 5 | Attestation module | ~6 tests |
| 6 | Integration tests | ~5 tests |

**Total: ~50 new tests**
