# Key Ceremony Manager — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the updated Key Ceremony Manager as a stateful GenServer process with multi-manager authorization, auditor finalization, and custodian share distribution where shares are returned to custodians (not stored in DB).

**Architecture:** The ceremony runs as a GenServer process. Multiple Key Managers must start it (policy-driven). The ceremony progresses through phases: Setup → Key Generation → Certificate Binding → Custodian Assignment → Finalization. The Auditor must cryptographically sign the audit trail to finalize.

**Spec:** `docs/superpowers/specs/2026-03-26-beta2-multi-tenancy-crypto-credentials.md` Section 6

**Depends on:** Plan 4 (Key Vault) — completed

---

### Task 1: Create KeyCeremonyManager GenServer

Stateful process that tracks ceremony phases and authorized sessions.

### Task 2: Multi-manager authorization

`start/1` requires a list of authorized sessions. System verifies all sessions belong to users with `key_admin` role.

### Task 3: Keypair generation phase

`generate_keypair/2` generates keypair, stores encrypted in vault with chosen protection mode.

### Task 4: Certificate binding

`gen_self_sign_cert/3` for root issuers, `gen_csr/2` for sub-CA issuers.

### Task 5: Custodian share assignment

`assign_custodians/3` splits the activation password/key per protection policy. Each custodian provides their password, receives an encrypted share. Shares NOT stored in DB.

### Task 6: Auditor finalization

`finalize/2` requires an auditor session. The auditor signs the ceremony audit trail. Returns signed audit trail for safe keeping.

### Task 7: Integration test — full ceremony flow

---

## Plan Summary

| Task | What | Tests |
|------|------|-------|
| 1 | GenServer skeleton + phases | ~6 tests |
| 2 | Multi-manager auth | ~4 tests |
| 3 | Keypair generation | ~4 tests |
| 4 | Certificate binding | ~4 tests |
| 5 | Custodian shares | ~6 tests |
| 6 | Auditor finalization | ~4 tests |
| 7 | Full ceremony integration | ~3 tests |

**Total: ~30 new tests**
